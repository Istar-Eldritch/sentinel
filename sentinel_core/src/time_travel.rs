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

use crate::aggregate::{POLICY_AGGREGATE_ID, PolicyAggregate, PolicyEvent, PolicyState};
use crate::{AccessRequest, AccessScope, Decision, PolicyGraph, ScopeRequest, evaluate, scope};

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

    /// Runs [`evaluate`] against the policy graph as it existed at time `t`.
    ///
    /// Reconstructs the graph once via [`policy_at`](Self::policy_at) and
    /// dispatches to the unchanged [`evaluate`]. Returns [`Decision::Deny`]
    /// (fail-closed) when `t` predates the first policy event — the graph did
    /// not exist, so nothing is authorized.
    pub async fn evaluate_at(
        &self,
        t: DateTime<Utc>,
        request: &AccessRequest,
    ) -> Result<Decision, TimeTravelError> {
        Ok(match self.policy_at(t).await? {
            Some(graph) => evaluate(&graph, request),
            None => Decision::Deny,
        })
    }

    /// Runs [`scope`] against the policy graph as it existed at time `t`.
    ///
    /// Reconstructs the graph once via [`policy_at`](Self::policy_at) and
    /// dispatches to the unchanged [`scope`]. Returns [`AccessScope::None`]
    /// (fail-closed) when `t` predates the first policy event.
    pub async fn scope_at(
        &self,
        t: DateTime<Utc>,
        request: &ScopeRequest,
    ) -> Result<AccessScope, TimeTravelError> {
        Ok(match self.policy_at(t).await? {
            Some(graph) => scope(&graph, request),
            None => AccessScope::None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregate::{PolicyActor, PolicyCommand};
    use crate::{AssociationTarget, AttributeMatcher, ScopeConstraint};
    use std::collections::HashSet;

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

    fn event_at(data: PolicyEvent, version: u64, created_at: DateTime<Utc>) -> Event<PolicyEvent> {
        data.into_builder()
            .stream_id(POLICY_AGGREGATE_ID)
            .stream_version(version)
            .created_at(created_at)
            .build()
            .unwrap()
    }

    fn attrs(pairs: &[(&str, &[&str])]) -> std::collections::HashMap<String, HashSet<String>> {
        pairs
            .iter()
            .map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect()))
            .collect()
    }

    fn scope_admits(
        s: &AccessScope,
        resource_attrs: &std::collections::HashMap<String, HashSet<String>>,
    ) -> bool {
        match s {
            AccessScope::Unrestricted => true,
            AccessScope::None => false,
            AccessScope::Constrained(constraints) => constraints.iter().any(|c| {
                let ScopeConstraint::Attribute { key, values } = c;
                resource_attrs
                    .get(key)
                    .is_some_and(|vs| vs.iter().any(|v| values.contains(v)))
            }),
        }
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

    #[tokio::test]
    async fn evaluate_at_and_scope_at_now_match_present_day() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let cmds = vec![
            PolicyCommand::CreateUserAttribute {
                id: ua_id,
                name: "admins".to_string(),
                matcher: AttributeMatcher::Matching {
                    key: "role".to_string(),
                    values: vec!["admin".to_string()],
                },
            },
            PolicyCommand::CreatePolicyClass {
                id: pc_id,
                name: "org_pc".to_string(),
            },
            PolicyCommand::CreateObjectAttribute {
                id: oa_id,
                name: "alpha_jobs".to_string(),
                resource_type: "job".to_string(),
                matcher: AttributeMatcher::Matching {
                    key: "org_id".to_string(),
                    values: vec!["alpha".to_string()],
                },
            },
            PolicyCommand::AssignOaToPc { oa_id, pc_id },
            PolicyCommand::CreateAssociation {
                ua_id,
                target: AssociationTarget::PolicyClass(pc_id),
                operations: HashSet::from(["read".to_string()]),
            },
        ];
        for c in cmds {
            agg.handle(Command::new(
                POLICY_AGGREGATE_ID,
                c,
                Some(PolicyActor { id: Uuid::new_v4() }),
                None,
            ))
            .await
            .unwrap();
        }

        let present = agg
            .get_state_store()
            .get_state(POLICY_AGGREGATE_ID)
            .await
            .unwrap()
            .unwrap()
            .graph;
        let subject = attrs(&[("role", &["admin"])]);
        let areq = AccessRequest::new("read", "job")
            .subject_attrs(subject.clone())
            .resource_attrs(attrs(&[("org_id", &["alpha"])]));
        let sreq = ScopeRequest::new("read", "job").subject_attrs(subject);

        let now = Utc::now();
        assert_eq!(
            agg.evaluate_at(now, &areq).await.unwrap(),
            evaluate(&present, &areq)
        );
        assert_eq!(
            agg.scope_at(now, &sreq).await.unwrap(),
            scope(&present, &sreq)
        );
    }

    #[tokio::test]
    async fn evaluate_at_flips_across_grant() {
        let agg = make_aggregate();
        let t1 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let grant_t = t1 + Duration::seconds(100);
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();

        agg.get_event_store()
            .store_events(vec![
                event_at(
                    PolicyEvent::UserAttributeCreated {
                        id: ua_id,
                        name: "admins".to_string(),
                        matcher: AttributeMatcher::All,
                    },
                    1,
                    t1,
                ),
                event_at(
                    PolicyEvent::ObjectAttributeCreated {
                        id: oa_id,
                        name: "all_jobs".to_string(),
                        resource_type: "job".to_string(),
                        matcher: AttributeMatcher::All,
                    },
                    2,
                    t1,
                ),
                event_at(
                    PolicyEvent::AssociationCreated {
                        ua_id,
                        target: AssociationTarget::ObjectAttribute(oa_id),
                        operations: HashSet::from(["read".to_string()]),
                    },
                    3,
                    grant_t,
                ),
            ])
            .await
            .unwrap();

        let req = AccessRequest::new("read", "job");
        assert_eq!(
            agg.evaluate_at(grant_t - Duration::seconds(1), &req)
                .await
                .unwrap(),
            Decision::Deny
        );
        assert_eq!(
            agg.evaluate_at(grant_t + Duration::seconds(1), &req)
                .await
                .unwrap(),
            Decision::Allow
        );
    }

    #[tokio::test]
    async fn soundness_invariant_holds_on_reconstructed_graph() {
        let agg = make_aggregate();
        let t1 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();

        // Org-scoped admin pattern (Constrained scope), built via events.
        agg.get_event_store()
            .store_events(vec![
                event_at(
                    PolicyEvent::UserAttributeCreated {
                        id: ua_id,
                        name: "org_alpha_admins".to_string(),
                        matcher: AttributeMatcher::Matching {
                            key: "role".to_string(),
                            values: vec!["admin".to_string()],
                        },
                    },
                    1,
                    t1,
                ),
                event_at(
                    PolicyEvent::PolicyClassCreated {
                        id: pc_id,
                        name: "org_alpha_pc".to_string(),
                    },
                    2,
                    t1,
                ),
                event_at(
                    PolicyEvent::ObjectAttributeCreated {
                        id: oa_id,
                        name: "alpha_jobs".to_string(),
                        resource_type: "job".to_string(),
                        matcher: AttributeMatcher::Matching {
                            key: "org_id".to_string(),
                            values: vec!["alpha".to_string()],
                        },
                    },
                    3,
                    t1,
                ),
                event_at(PolicyEvent::OaAssignedToPc { oa_id, pc_id }, 4, t1),
                event_at(
                    PolicyEvent::AssociationCreated {
                        ua_id,
                        target: AssociationTarget::PolicyClass(pc_id),
                        operations: HashSet::from(["read".to_string()]),
                    },
                    5,
                    t1,
                ),
            ])
            .await
            .unwrap();

        let historical_t = t1 + Duration::seconds(10);
        let graph = agg
            .policy_at(historical_t)
            .await
            .unwrap()
            .expect("graph exists at historical t");
        let subject = attrs(&[("role", &["admin"])]);
        let resources = [
            attrs(&[("org_id", &["alpha"])]),
            attrs(&[("org_id", &["alpha", "beta"])]),
            attrs(&[("org_id", &["beta"])]),
            attrs(&[]),
        ];

        let sreq = ScopeRequest::new("read", "job").subject_attrs(subject.clone());
        let s = agg.scope_at(historical_t, &sreq).await.unwrap();
        // scope_at and scope() agree on the reconstructed graph.
        assert_eq!(s, scope(&graph, &sreq));

        for resource in &resources {
            let admitted = scope_admits(&s, resource);
            let areq = AccessRequest::new("read", "job")
                .subject_attrs(subject.clone())
                .resource_attrs(resource.clone());
            let allowed = agg.evaluate_at(historical_t, &areq).await.unwrap() == Decision::Allow;
            assert_eq!(
                admitted, allowed,
                "soundness violated for {resource:?}: scope_admits={admitted}, allowed={allowed}"
            );
        }
    }

    #[tokio::test]
    async fn pre_history_is_fail_closed() {
        let agg = make_aggregate();
        let t1 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        agg.get_event_store()
            .store_events(vec![ua_event("first", 1, t1)])
            .await
            .unwrap();

        let before = t1 - Duration::seconds(1);
        assert_eq!(
            agg.scope_at(before, &ScopeRequest::new("read", "job"))
                .await
                .unwrap(),
            AccessScope::None
        );
        assert_eq!(
            agg.evaluate_at(before, &AccessRequest::new("read", "job"))
                .await
                .unwrap(),
            Decision::Deny
        );
    }
}
