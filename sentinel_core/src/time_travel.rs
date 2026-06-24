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
//! ## Clock-skew and under-reporting
//!
//! Timestamp→version translation uses the longest **contiguous prefix** of
//! events whose `created_at ≤ t` (see [`policy_version_at`]). This is the
//! fail-closed guarantee: an out-of-order (clock-skewed) event at version `k`
//! with a future timestamp terminates the prefix at `k-1`, so all queries
//! whose target time falls between the real event time and the skewed timestamp
//! will see the policy as of version `k-1` — hiding legitimately committed
//! later policy. This is the safe direction for authorization audits, but
//! operators should be aware that skewed clocks can make historical views
//! shorter than reality.
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
    /// Returns the highest `stream_version` `V` such that *every* event in the
    /// prefix `[1, V]` has `created_at <= t`, or `None` when the first event
    /// already postdates `t`.
    ///
    /// Reconstruction is prefix-based (snapshot + bounded replay up to a
    /// version), so the only sound translation is the longest contiguous prefix
    /// that fully precedes `t`. epoch's event store guarantees ascending
    /// `stream_version` order but *not* `created_at` monotonicity, so we stop at
    /// the first event after `t` rather than taking the max matching version:
    /// an out-of-order event (clock skew) must never pull a later-timestamped
    /// event into a historical view, which would be a fail-open violation of the
    /// soundness invariant.
    ///
    /// **Performance:** this always performs a full O(n) scan of the event
    /// stream (via `read_events_range(.., None, None)`). The translation is
    /// intentionally not snapshot-accelerated — snapshots record state, not
    /// timestamps, so there is no shortcut. At the stated scale of hundreds of
    /// policy events this is fine.
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
            if event.created_at > t {
                break;
            }
            version = Some(event.stream_version);
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
    ///
    /// **Reconstruction cost:** each call reconstructs the full graph. If you
    /// need to evaluate many requests at the same `t`, call [`policy_at`] once
    /// and pass the returned graph directly to [`evaluate`] instead.
    ///
    /// [`policy_at`]: Self::policy_at
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
    ///
    /// **Reconstruction cost:** each call reconstructs the full graph. If you
    /// need to resolve scope for many requests at the same `t`, call
    /// [`policy_at`] once and pass the returned graph directly to [`scope`]
    /// instead.
    ///
    /// [`policy_at`]: Self::policy_at
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
    use epoch_core::prelude::{Command, Event, SnapshotConfig, SnapshotRetention, SnapshotTrigger};
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
    async fn out_of_order_timestamp_does_not_pull_in_future_events() {
        // epoch guarantees ascending stream_version, not created_at monotonicity.
        // A higher-version event with an earlier timestamp must not cause an
        // intervening future-timestamped event to be included in the view.
        let agg = make_aggregate();
        let early = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let future = early + Duration::seconds(1_000);
        let late = early + Duration::seconds(10);

        // v1 @ early, v2 @ future (out-of-order: postdates v3), v3 @ late.
        agg.get_event_store()
            .store_events(vec![
                ua_event("first", 1, early),
                ua_event("second", 2, future),
                ua_event("third", 3, late),
            ])
            .await
            .unwrap();

        // Querying at `late`: only the contiguous prefix [v1] fully precedes it,
        // because v2 (the next event) postdates `late`. v3 must not be pulled in.
        assert_eq!(agg.policy_version_at(late).await.unwrap(), Some(1));
        let graph = agg.policy_at(late).await.unwrap().unwrap();
        assert_eq!(graph.user_attributes.len(), 1);
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

    #[tokio::test]
    async fn snapshot_backed_reconstruction() {
        // Verifies that policy_at_version composes correctly with a snapshot
        // start-state (snapshot + bounded replay) rather than always doing a
        // full replay from version 1.
        let bus = InMemoryEventBus::<PolicyEvent>::new();
        let event_store = InMemoryEventStore::new(bus);
        let state_store = InMemoryStateStore::<PolicyState>::new();
        let snapshot_store = InMemorySnapshotStore::<PolicyState>::new();
        let agg = PolicyAggregate::new(event_store, state_store, snapshot_store.clone())
            .with_snapshot_config(SnapshotConfig {
                trigger: SnapshotTrigger::Automatic { interval: 3 },
                retention: SnapshotRetention::KeepLast(5),
            });

        // Drive 5 commands (versions 1–5); interval=3 fires a snapshot at v3.
        for i in 0..5usize {
            agg.handle(create_ua_command(&format!("ua{i}")))
                .await
                .unwrap();
        }

        // A snapshot must have been captured at the interval boundary (v3).
        let snap = snapshot_store
            .load_snapshot(POLICY_AGGREGATE_ID, 3)
            .await
            .unwrap()
            .expect("snapshot captured at version 3 interval boundary");
        assert_eq!(snap.version, 3);
        assert_eq!(snap.state.graph.user_attributes.len(), 3);

        // Reconstruct at v5 — uses snapshot @ v3 + bounded replay of v4, v5.
        let graph = agg
            .policy_at_version(5)
            .await
            .unwrap()
            .expect("graph exists at version 5");
        assert_eq!(graph.user_attributes.len(), 5);
    }

    #[tokio::test]
    async fn node_deletion_across_time() {
        let agg = make_aggregate();
        let t1 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let t2 = t1 + Duration::seconds(100);
        let ua_id = Uuid::new_v4();

        agg.get_event_store()
            .store_events(vec![
                event_at(
                    PolicyEvent::UserAttributeCreated {
                        id: ua_id,
                        name: "temp_ua".to_string(),
                        matcher: AttributeMatcher::All,
                    },
                    1,
                    t1,
                ),
                event_at(PolicyEvent::UserAttributeDeleted { id: ua_id }, 2, t2),
            ])
            .await
            .unwrap();

        let before = agg
            .policy_at(t1 + Duration::seconds(1))
            .await
            .unwrap()
            .expect("graph present before deletion");
        assert_eq!(
            before.user_attributes.len(),
            1,
            "node present before deletion"
        );

        let after = agg
            .policy_at(t2 + Duration::seconds(1))
            .await
            .unwrap()
            .expect("graph present after deletion");
        assert_eq!(after.user_attributes.len(), 0, "node gone after deletion");
    }

    #[tokio::test]
    async fn exact_timestamp_boundary_is_inclusive() {
        // created_at > t means t == created_at includes that event.
        let agg = make_aggregate();
        let t1 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        agg.get_event_store()
            .store_events(vec![ua_event("first", 1, t1)])
            .await
            .unwrap();

        assert_eq!(
            agg.policy_version_at(t1).await.unwrap(),
            Some(1),
            "event at exactly t1 is included (boundary is inclusive)"
        );
    }

    #[tokio::test]
    async fn empty_stream_returns_none() {
        let agg = make_aggregate();
        assert_eq!(agg.policy_version_at(Utc::now()).await.unwrap(), None);
        assert!(agg.policy_at(Utc::now()).await.unwrap().is_none());
    }
}
