//! # Time-Travel Authorization
//!
//! Reconstructs the policy graph as it existed at a past instant so the same
//! authorization queries can be answered against historical policy state.
//!
//! The substrate is the policy event stream: [`policy_version_at`] translates a
//! wall-clock time into a `stream_version`, and [`policy_at`] /
//! [`policy_at_version`] reconstruct the [`PolicyGraph`] at that point via
//! epoch's `state_at` (nearest snapshot + bounded replay).
//!
//! [`policy_version_at`]: PolicyAggregate::policy_version_at
//! [`policy_at`]: PolicyAggregate::policy_at
//! [`policy_at_version`]: PolicyAggregate::policy_at_version

use chrono::{DateTime, Utc};

use epoch_core::prelude::*;
use tokio_stream::StreamExt;

use crate::PolicyGraph;
use crate::aggregate::{POLICY_AGGREGATE_ID, PolicyAggregate, PolicyEvent, PolicyState};

/// I/O failures encountered while reconstructing historical policy state.
///
/// These wrap event-store and snapshot-store read failures surfaced by epoch's
/// `read_events_range` / `state_at`. They are operational errors, not policy
/// decisions — a reconstruction that succeeds against an empty graph is a valid
/// (fail-closed) result, not an error.
#[derive(Debug, thiserror::Error)]
pub enum TimeTravelError {
    /// The event store failed while scanning the policy stream for timestamps.
    #[error("event store error: {0}")]
    EventStore(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Reconstruction (snapshot load + bounded replay) failed.
    #[error("reconstruction error: {0}")]
    Reconstruction(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl<ES, SS, SNS> PolicyAggregate<ES, SS, SNS>
where
    ES: EventStoreBackend<EventType = PolicyEvent> + Send + Sync + Clone + 'static,
    SS: StateStoreBackend<PolicyState> + Send + Sync + Clone,
    SNS: SnapshotStore<PolicyState> + Send + Sync + Clone,
    ES::Error: 'static,
    SNS::Error: 'static,
{
    /// Returns the `stream_version` of the last policy event whose `created_at`
    /// is at or before `t`, or `None` if no event exists at or before `t`.
    ///
    /// This is the timestamp → version translation that underpins
    /// [`policy_at`](Self::policy_at).
    pub async fn policy_version_at(
        &self,
        t: DateTime<Utc>,
    ) -> Result<Option<u64>, TimeTravelError> {
        let event_store = self.get_event_store();
        let mut stream = event_store
            .read_events_range(POLICY_AGGREGATE_ID, None, None)
            .await
            .map_err(|e| TimeTravelError::EventStore(Box::new(e)))?;

        let mut version: Option<u64> = None;
        while let Some(item) = stream.next().await {
            let event = item.map_err(|e| TimeTravelError::EventStore(Box::new(e)))?;
            if event.created_at <= t {
                version =
                    Some(version.map_or(event.stream_version, |v| v.max(event.stream_version)));
            }
        }
        Ok(version)
    }

    /// Reconstructs the [`PolicyGraph`] as it existed at time `t`.
    ///
    /// Translates `t` to a version via [`policy_version_at`](Self::policy_version_at)
    /// and reconstructs at that version. Returns `None` when `t` predates the
    /// first policy event (the graph "did not exist").
    pub async fn policy_at(
        &self,
        t: DateTime<Utc>,
    ) -> Result<Option<PolicyGraph>, TimeTravelError> {
        match self.policy_version_at(t).await? {
            Some(version) => self.policy_at_version(version).await,
            None => Ok(None),
        }
    }

    /// Reconstructs the [`PolicyGraph`] at an explicit `stream_version`.
    ///
    /// Lower-level primitive that skips timestamp translation. Composes the
    /// nearest snapshot at or before `version` with a bounded replay of the
    /// remaining events. Returns `None` when no events exist at or before
    /// `version`.
    pub async fn policy_at_version(
        &self,
        version: u64,
    ) -> Result<Option<PolicyGraph>, TimeTravelError> {
        let event_store = self.get_event_store();
        let snapshot_store = self.snapshot_store();
        let state = state_at(
            self,
            &event_store,
            &snapshot_store,
            POLICY_AGGREGATE_ID,
            version,
        )
        .await
        .map_err(|e| TimeTravelError::Reconstruction(Box::new(e)))?;
        Ok(state.map(|s| s.graph))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttributeMatcher;
    use crate::aggregate::{PolicyActor, PolicyCommand};

    use chrono::{Duration, TimeZone};
    use epoch_core::prelude::{Command, Event};
    use epoch_mem::{
        InMemoryEventBus, InMemoryEventStore, InMemorySnapshotStore, InMemoryStateStore,
    };
    use uuid::Uuid;

    type TestAggregate = PolicyAggregate<
        InMemoryEventStore<InMemoryEventBus<PolicyEvent>>,
        InMemoryStateStore<PolicyState>,
        InMemorySnapshotStore<PolicyState>,
    >;

    fn make_aggregate() -> TestAggregate {
        let bus = InMemoryEventBus::<PolicyEvent>::new();
        let event_store = InMemoryEventStore::new(bus);
        let state_store = InMemoryStateStore::<PolicyState>::new();
        let snapshot_store = InMemorySnapshotStore::<PolicyState>::new();
        PolicyAggregate::new(event_store, state_store, snapshot_store)
    }

    fn create_ua_command(name: &str) -> Command<PolicyCommand, PolicyActor> {
        Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreateUserAttribute {
                id: Uuid::new_v4(),
                name: name.to_string(),
                matcher: AttributeMatcher::All,
            },
            Some(PolicyActor { id: Uuid::new_v4() }),
            None,
        )
    }

    fn ua_event(name: &str, version: u64, created_at: DateTime<Utc>) -> Event<PolicyEvent> {
        PolicyEvent::UserAttributeCreated {
            id: Uuid::new_v4(),
            name: name.to_string(),
            matcher: AttributeMatcher::All,
        }
        .into_builder()
        .stream_id(POLICY_AGGREGATE_ID)
        .stream_version(version)
        .created_at(created_at)
        .build()
        .unwrap()
    }

    #[tokio::test]
    async fn policy_at_now_equals_present_day_state() {
        let agg = make_aggregate();
        for name in ["a", "b", "c"] {
            agg.handle(create_ua_command(name)).await.unwrap();
        }

        let present = agg
            .get_state_store()
            .get_state(POLICY_AGGREGATE_ID)
            .await
            .unwrap()
            .expect("live state present after commands")
            .graph;

        let reconstructed = agg
            .policy_at(Utc::now())
            .await
            .unwrap()
            .expect("graph exists at now");

        assert_eq!(
            reconstructed.user_attributes.len(),
            present.user_attributes.len()
        );
        assert_eq!(reconstructed.user_attributes.len(), 3);
        let present_ids: std::collections::HashSet<_> =
            present.user_attributes.keys().copied().collect();
        let reconstructed_ids: std::collections::HashSet<_> =
            reconstructed.user_attributes.keys().copied().collect();
        assert_eq!(reconstructed_ids, present_ids);
    }

    #[tokio::test]
    async fn version_boundary_separates_graphs_and_timestamps() {
        let agg = make_aggregate();
        let t1 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let t2 = t1 + Duration::seconds(10);

        agg.get_event_store()
            .store_events(vec![ua_event("first", 1, t1), ua_event("second", 2, t2)])
            .await
            .unwrap();

        // Reconstruction across the version boundary V=2 differs.
        let before = agg.policy_at_version(1).await.unwrap().unwrap();
        let after = agg.policy_at_version(2).await.unwrap().unwrap();
        assert_eq!(before.user_attributes.len(), 1);
        assert_eq!(after.user_attributes.len(), 2);

        // Timestamp translation brackets the boundary (T = t2).
        let just_before = agg
            .policy_version_at(t2 - Duration::seconds(1))
            .await
            .unwrap();
        let just_after = agg
            .policy_version_at(t2 + Duration::seconds(1))
            .await
            .unwrap();
        assert_eq!(just_before, Some(1));
        assert_eq!(just_after, Some(2));
        assert!(just_before < just_after);
    }

    #[tokio::test]
    async fn policy_at_before_first_event_is_none() {
        let agg = make_aggregate();
        let t1 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        agg.get_event_store()
            .store_events(vec![ua_event("first", 1, t1)])
            .await
            .unwrap();

        assert_eq!(
            agg.policy_version_at(t1 - Duration::seconds(1))
                .await
                .unwrap(),
            None
        );
        assert!(
            agg.policy_at(t1 - Duration::seconds(1))
                .await
                .unwrap()
                .is_none()
        );
    }
}
