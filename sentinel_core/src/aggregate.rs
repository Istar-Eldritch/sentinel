//! # Policy Aggregate
//!
//! Event-sourced persistence layer for the policy graph, using the
//! [epoch](https://github.com/Istar-Eldritch/epoch) CQRS/event-sourcing framework.
//!
//! This module defines:
//! - [`PolicyEvent`] — events emitted by policy mutations
//! - [`PolicyCommand`] — commands that mutate the policy graph
//! - [`PolicyState`] — the persisted aggregate state wrapping [`PolicyGraph`]
//! - [`PolicyAggregate`] — the event-sourced aggregate handling commands and applying events
//! - [`PolicyActor`] — credentials carrying the actor ID for audit trails

use std::collections::HashSet;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::{Uuid, uuid};

use epoch_core::prelude::*;
use epoch_derive::EventData;

use crate::{
    Association, AssociationTarget, AttributeMatcher, ObjectAttribute, PolicyClass, PolicyGraph,
    UserAttribute,
};

/// The well-known fixed UUID for the single policy aggregate.
///
/// All policy commands must target this ID. There is exactly one
/// policy aggregate per application instance.
pub const POLICY_AGGREGATE_ID: Uuid = uuid!("a1b2c3d4-e5f6-7890-abcd-ef1234567890");

/// Credentials for policy commands, carrying the actor ID for audit purposes.
///
/// Every policy mutation is stamped with the actor ID on the produced event,
/// providing a full audit trail of who made each policy change.
#[derive(Debug, Clone)]
pub struct PolicyActor {
    /// The unique identifier of the actor performing the policy mutation.
    pub id: Uuid,
}

/// Commands that mutate the policy graph.
///
/// Each variant represents an intention to change the policy graph. Commands
/// are validated by [`PolicyAggregate`] before producing events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCommand {
    /// Create a new user attribute node.
    CreateUserAttribute {
        /// The unique ID for this user attribute.
        id: Uuid,
        /// Human-readable name.
        name: String,
        /// Matcher determining which subjects fall under this UA.
        matcher: AttributeMatcher,
    },
    /// Create a new object attribute node.
    CreateObjectAttribute {
        /// The unique ID for this object attribute.
        id: Uuid,
        /// Human-readable name.
        name: String,
        /// The resource type this OA applies to.
        resource_type: String,
        /// Matcher determining which resources fall under this OA.
        matcher: AttributeMatcher,
    },
    /// Create a new policy class node.
    CreatePolicyClass {
        /// The unique ID for this policy class.
        id: Uuid,
        /// Human-readable name.
        name: String,
    },
    /// Set the operation set for a permission association from a UA to a target.
    ///
    /// If an association for the same `(ua_id, target)` pair already exists,
    /// it is replaced (upsert semantics, D19). The second `CreateAssociation`
    /// for a pair becomes the canonical grant; replaying the event log is
    /// therefore coherent even when the same pair appears multiple times.
    CreateAssociation {
        /// The user attribute this association originates from.
        ua_id: Uuid,
        /// The target (OA or PC) of this permission grant.
        target: AssociationTarget,
        /// The set of permitted operations.
        operations: HashSet<String>,
    },
    /// Remove a permission association.
    RemoveAssociation {
        /// The user attribute of the association to remove.
        ua_id: Uuid,
        /// The target of the association to remove.
        target: AssociationTarget,
    },
    /// Assign an object attribute to a policy class.
    AssignOaToPc {
        /// The object attribute to assign.
        oa_id: Uuid,
        /// The policy class to assign to.
        pc_id: Uuid,
    },
    /// Remove an OA→PC assignment.
    UnassignOaFromPc {
        /// The object attribute to unassign.
        oa_id: Uuid,
        /// The policy class to unassign from.
        pc_id: Uuid,
    },
    /// Delete a user attribute node and cascade-remove all dependent edges.
    DeleteUserAttribute {
        /// The ID of the user attribute to delete.
        id: Uuid,
    },
    /// Delete an object attribute node and cascade-remove all dependent edges.
    DeleteObjectAttribute {
        /// The ID of the object attribute to delete.
        id: Uuid,
    },
    /// Delete a policy class node and cascade-remove all dependent edges.
    DeletePolicyClass {
        /// The ID of the policy class to delete.
        id: Uuid,
    },
}

/// Events emitted by the policy aggregate.
///
/// Events mirror commands 1:1 with past-tense naming. Each event carries
/// exactly the data needed to replay the corresponding [`PolicyGraph`]
/// mutation.
///
/// `PolicyEvent` serves as both the superset event type (`ED` in `Aggregate<ED>`)
/// and the subset `EventType` — no `#[subset_enum]` is needed since sentinel
/// has a single aggregate.
#[derive(Debug, Clone, Serialize, Deserialize, EventData)]
pub enum PolicyEvent {
    /// A user attribute node was created.
    UserAttributeCreated {
        /// The unique ID of the created user attribute.
        id: Uuid,
        /// Human-readable name.
        name: String,
        /// Matcher determining which subjects fall under this UA.
        matcher: AttributeMatcher,
    },
    /// An object attribute node was created.
    ObjectAttributeCreated {
        /// The unique ID of the created object attribute.
        id: Uuid,
        /// Human-readable name.
        name: String,
        /// The resource type this OA applies to.
        resource_type: String,
        /// Matcher determining which resources fall under this OA.
        matcher: AttributeMatcher,
    },
    /// A policy class node was created.
    PolicyClassCreated {
        /// The unique ID of the created policy class.
        id: Uuid,
        /// Human-readable name.
        name: String,
    },
    /// A permission association was created.
    AssociationCreated {
        /// The user attribute this association originates from.
        ua_id: Uuid,
        /// The target (OA or PC) of this permission grant.
        target: AssociationTarget,
        /// The set of permitted operations.
        operations: HashSet<String>,
    },
    /// A permission association was removed.
    AssociationRemoved {
        /// The user attribute of the removed association.
        ua_id: Uuid,
        /// The target of the removed association.
        target: AssociationTarget,
    },
    /// An OA was assigned to a PC.
    OaAssignedToPc {
        /// The object attribute that was assigned.
        oa_id: Uuid,
        /// The policy class that was assigned to.
        pc_id: Uuid,
    },
    /// An OA was unassigned from a PC.
    OaUnassignedFromPc {
        /// The object attribute that was unassigned.
        oa_id: Uuid,
        /// The policy class that was unassigned from.
        pc_id: Uuid,
    },
    /// A user attribute node was deleted.
    UserAttributeDeleted {
        /// The ID of the deleted user attribute.
        id: Uuid,
    },
    /// An object attribute node was deleted.
    ObjectAttributeDeleted {
        /// The ID of the deleted object attribute.
        id: Uuid,
    },
    /// A policy class node was deleted.
    PolicyClassDeleted {
        /// The ID of the deleted policy class.
        id: Uuid,
    },
}

impl TryFrom<&PolicyEvent> for PolicyEvent {
    type Error = EnumConversionError;

    fn try_from(value: &PolicyEvent) -> Result<Self, Self::Error> {
        Ok(value.clone())
    }
}

/// The persisted state of the policy aggregate.
///
/// Wraps a [`PolicyGraph`] with epoch version tracking.
/// Access `state.graph` directly for PEP evaluation:
///
/// ```ignore
/// let state = aggregate.handle(command).await?.unwrap();
/// let decision = evaluate(&state.graph, &request);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyState {
    /// The current policy graph. Read directly for PEP evaluation.
    pub graph: PolicyGraph,
    /// Epoch version counter — managed exclusively by epoch machinery.
    version: u64,
}

impl EventApplicatorState for PolicyState {
    fn get_id(&self) -> &Uuid {
        &POLICY_AGGREGATE_ID
    }
}

impl AggregateState for PolicyState {
    fn get_version(&self) -> u64 {
        self.version
    }

    fn set_version(&mut self, version: u64) {
        self.version = version;
    }
}

/// Error type for [`PolicyAggregate`]'s event application.
///
/// The only failure mode is a purged event whose `data` field is `None`.
/// Sentinel does **not** support purging policy events; a missing-data event
/// in the policy stream is treated as a hard error that fails replay closed
/// rather than silently skipping the grant (D20).
#[derive(Debug, thiserror::Error)]
pub enum PolicyApplyError {
    /// Event data is absent (purged event). Policy-event purging is not
    /// supported; replay fails closed rather than skipping the grant.
    #[error("Missing event data for event {0}")]
    MissingEventData(Uuid),
}

/// Error type for [`PolicyAggregate`]'s command handling.
#[derive(Debug, thiserror::Error)]
pub enum PolicyCommandError {
    /// Failed to build an event.
    #[error("Error building event: {0}")]
    EventBuild(#[from] EventBuilderError),

    /// A referenced user attribute does not exist in the graph.
    #[error("User attribute {0} not found")]
    UserAttributeNotFound(Uuid),

    /// A referenced object attribute does not exist in the graph.
    #[error("Object attribute {0} not found")]
    ObjectAttributeNotFound(Uuid),

    /// A referenced policy class does not exist in the graph.
    #[error("Policy class {0} not found")]
    PolicyClassNotFound(Uuid),
}

/// Default snapshot capture/retention policy for [`PolicyAggregate`].
///
/// Captures a snapshot every 50 versions and retains the most recent 5. Policy
/// streams are small (hundreds of events), so this keeps reconstruction fast
/// without unbounded snapshot growth.
fn default_snapshot_config() -> SnapshotConfig {
    SnapshotConfig {
        trigger: SnapshotTrigger::Automatic { interval: 50 },
        retention: SnapshotRetention::KeepLast(5),
    }
}

/// The event-sourced policy aggregate.
///
/// Generic over the event store (`ES`), state store (`SS`), and snapshot store
/// (`SNS`) backends, so the consuming application or tests supply the concrete
/// implementations.
///
/// # Example (with in-memory backends for testing)
///
/// ```ignore
/// use epoch_mem::{
///     InMemoryEventBus, InMemoryEventStore, InMemorySnapshotStore, InMemoryStateStore,
/// };
///
/// let bus = InMemoryEventBus::<PolicyEvent>::new();
/// let event_store = InMemoryEventStore::new(bus);
/// let state_store = InMemoryStateStore::<PolicyState>::new();
/// let snapshot_store = InMemorySnapshotStore::<PolicyState>::new();
/// let aggregate = PolicyAggregate::new(event_store, state_store, snapshot_store);
/// ```
pub struct PolicyAggregate<ES, SS, SNS> {
    event_store: ES,
    state_store: SS,
    snapshot_store: SNS,
    snapshot_config: SnapshotConfig,
}

impl<ES, SS, SNS> PolicyAggregate<ES, SS, SNS> {
    /// Creates a new `PolicyAggregate` with the given event, state, and snapshot
    /// stores and the [default snapshot config](default_snapshot_config).
    pub fn new(event_store: ES, state_store: SS, snapshot_store: SNS) -> Self {
        Self {
            event_store,
            state_store,
            snapshot_store,
            snapshot_config: default_snapshot_config(),
        }
    }

    /// Overrides the snapshot capture/retention config.
    pub fn with_snapshot_config(mut self, config: SnapshotConfig) -> Self {
        self.snapshot_config = config;
        self
    }
}

impl<ES, SS, SNS> EventApplicator<PolicyEvent> for PolicyAggregate<ES, SS, SNS>
where
    ES: EventStoreBackend<EventType = PolicyEvent> + Send + Sync + Clone + 'static,
    SS: StateStoreBackend<PolicyState> + Send + Sync + Clone,
    SNS: SnapshotStore<PolicyState> + Send + Sync + Clone,
{
    type State = PolicyState;
    type StateStore = SS;
    type EventType = PolicyEvent;
    type ApplyError = PolicyApplyError;

    fn apply(
        &self,
        state: Option<PolicyState>,
        event: &Event<PolicyEvent>,
    ) -> Result<Option<PolicyState>, PolicyApplyError> {
        let mut state = state.unwrap_or_else(|| PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        });
        match event
            .data
            .as_ref()
            .ok_or(PolicyApplyError::MissingEventData(event.id))?
        {
            PolicyEvent::UserAttributeCreated { id, name, matcher } => {
                state.graph.add_ua(UserAttribute {
                    id: *id,
                    name: name.clone(),
                    matcher: matcher.clone(),
                });
            }
            PolicyEvent::ObjectAttributeCreated {
                id,
                name,
                resource_type,
                matcher,
            } => {
                state.graph.add_oa(ObjectAttribute {
                    id: *id,
                    name: name.clone(),
                    resource_type: resource_type.clone(),
                    matcher: matcher.clone(),
                });
            }
            PolicyEvent::PolicyClassCreated { id, name } => {
                state.graph.add_pc(PolicyClass {
                    id: *id,
                    name: name.clone(),
                });
            }
            PolicyEvent::AssociationCreated {
                ua_id,
                target,
                operations,
            } => {
                state.graph.add_association(Association {
                    ua_id: *ua_id,
                    target: target.clone(),
                    operations: operations.clone(),
                });
            }
            PolicyEvent::AssociationRemoved { ua_id, target } => {
                state.graph.remove_association(*ua_id, target);
            }
            PolicyEvent::OaAssignedToPc { oa_id, pc_id } => {
                state.graph.assign_oa_to_pc(*oa_id, *pc_id);
            }
            PolicyEvent::OaUnassignedFromPc { oa_id, pc_id } => {
                state.graph.unassign_oa_from_pc(*oa_id, *pc_id);
            }
            PolicyEvent::UserAttributeDeleted { id } => {
                state.graph.remove_ua(*id);
            }
            PolicyEvent::ObjectAttributeDeleted { id } => {
                state.graph.remove_oa(*id);
            }
            PolicyEvent::PolicyClassDeleted { id } => {
                state.graph.remove_pc(*id);
            }
        }
        Ok(Some(state))
    }

    fn get_state_store(&self) -> SS {
        self.state_store.clone()
    }
}

#[async_trait]
impl<ES, SS, SNS> Aggregate<PolicyEvent> for PolicyAggregate<ES, SS, SNS>
where
    ES: EventStoreBackend<EventType = PolicyEvent> + Send + Sync + Clone + 'static,
    SS: StateStoreBackend<PolicyState> + Send + Sync + Clone,
    SNS: SnapshotStore<PolicyState> + Send + Sync + Clone,
{
    type CommandData = PolicyCommand;
    type CommandCredentials = PolicyActor;
    type Command = PolicyCommand;
    type AggregateError = PolicyCommandError;
    type EventStore = ES;

    fn get_event_store(&self) -> ES {
        self.event_store.clone()
    }

    async fn handle_command(
        &self,
        state: &Option<PolicyState>,
        command: Command<PolicyCommand, PolicyActor>,
    ) -> Result<Vec<Event<PolicyEvent>>, PolicyCommandError> {
        let actor_id = command.credentials.as_ref().map(|a| a.id);

        let event_data = match command.data {
            PolicyCommand::CreateUserAttribute { id, name, matcher } => {
                PolicyEvent::UserAttributeCreated { id, name, matcher }
            }
            PolicyCommand::CreateObjectAttribute {
                id,
                name,
                resource_type,
                matcher,
            } => PolicyEvent::ObjectAttributeCreated {
                id,
                name,
                resource_type,
                matcher,
            },
            PolicyCommand::CreatePolicyClass { id, name } => {
                PolicyEvent::PolicyClassCreated { id, name }
            }
            PolicyCommand::CreateAssociation {
                ua_id,
                target,
                operations,
            } => {
                let graph = &state
                    .as_ref()
                    .ok_or(PolicyCommandError::UserAttributeNotFound(ua_id))?
                    .graph;
                if !graph.user_attributes.contains_key(&ua_id) {
                    return Err(PolicyCommandError::UserAttributeNotFound(ua_id));
                }
                match &target {
                    AssociationTarget::ObjectAttribute(oa_id) => {
                        if !graph.object_attributes.contains_key(oa_id) {
                            return Err(PolicyCommandError::ObjectAttributeNotFound(*oa_id));
                        }
                    }
                    AssociationTarget::PolicyClass(pc_id) => {
                        if !graph.policy_classes.contains_key(pc_id) {
                            return Err(PolicyCommandError::PolicyClassNotFound(*pc_id));
                        }
                    }
                }
                PolicyEvent::AssociationCreated {
                    ua_id,
                    target,
                    operations,
                }
            }
            PolicyCommand::RemoveAssociation { ua_id, target } => {
                let graph = &state
                    .as_ref()
                    .ok_or(PolicyCommandError::UserAttributeNotFound(ua_id))?
                    .graph;
                if !graph.user_attributes.contains_key(&ua_id) {
                    return Err(PolicyCommandError::UserAttributeNotFound(ua_id));
                }
                match &target {
                    AssociationTarget::ObjectAttribute(oa_id) => {
                        if !graph.object_attributes.contains_key(oa_id) {
                            return Err(PolicyCommandError::ObjectAttributeNotFound(*oa_id));
                        }
                    }
                    AssociationTarget::PolicyClass(pc_id) => {
                        if !graph.policy_classes.contains_key(pc_id) {
                            return Err(PolicyCommandError::PolicyClassNotFound(*pc_id));
                        }
                    }
                }
                PolicyEvent::AssociationRemoved { ua_id, target }
            }
            PolicyCommand::AssignOaToPc { oa_id, pc_id } => {
                let graph = &state
                    .as_ref()
                    .ok_or(PolicyCommandError::ObjectAttributeNotFound(oa_id))?
                    .graph;
                if !graph.object_attributes.contains_key(&oa_id) {
                    return Err(PolicyCommandError::ObjectAttributeNotFound(oa_id));
                }
                if !graph.policy_classes.contains_key(&pc_id) {
                    return Err(PolicyCommandError::PolicyClassNotFound(pc_id));
                }
                PolicyEvent::OaAssignedToPc { oa_id, pc_id }
            }
            PolicyCommand::UnassignOaFromPc { oa_id, pc_id } => {
                let graph = &state
                    .as_ref()
                    .ok_or(PolicyCommandError::ObjectAttributeNotFound(oa_id))?
                    .graph;
                if !graph.object_attributes.contains_key(&oa_id) {
                    return Err(PolicyCommandError::ObjectAttributeNotFound(oa_id));
                }
                if !graph.policy_classes.contains_key(&pc_id) {
                    return Err(PolicyCommandError::PolicyClassNotFound(pc_id));
                }
                PolicyEvent::OaUnassignedFromPc { oa_id, pc_id }
            }
            PolicyCommand::DeleteUserAttribute { id } => {
                let graph = &state
                    .as_ref()
                    .ok_or(PolicyCommandError::UserAttributeNotFound(id))?
                    .graph;
                if !graph.user_attributes.contains_key(&id) {
                    return Err(PolicyCommandError::UserAttributeNotFound(id));
                }
                PolicyEvent::UserAttributeDeleted { id }
            }
            PolicyCommand::DeleteObjectAttribute { id } => {
                let graph = &state
                    .as_ref()
                    .ok_or(PolicyCommandError::ObjectAttributeNotFound(id))?
                    .graph;
                if !graph.object_attributes.contains_key(&id) {
                    return Err(PolicyCommandError::ObjectAttributeNotFound(id));
                }
                PolicyEvent::ObjectAttributeDeleted { id }
            }
            PolicyCommand::DeletePolicyClass { id } => {
                let graph = &state
                    .as_ref()
                    .ok_or(PolicyCommandError::PolicyClassNotFound(id))?
                    .graph;
                if !graph.policy_classes.contains_key(&id) {
                    return Err(PolicyCommandError::PolicyClassNotFound(id));
                }
                PolicyEvent::PolicyClassDeleted { id }
            }
        };

        let mut builder = event_data.into_builder().stream_id(POLICY_AGGREGATE_ID);

        if let Some(id) = actor_id {
            builder = builder.actor_id(id);
        }

        let event = builder.build()?;
        Ok(vec![event])
    }

    async fn after_persist(
        &self,
        stream_id: Uuid,
        new_version: u64,
        events_applied: usize,
        state: &PolicyState,
    ) {
        self.capture_snapshot_if_due(stream_id, new_version, events_applied, state)
            .await;
    }
}

impl<ES, SS, SNS> SnapshottingAggregate<PolicyEvent> for PolicyAggregate<ES, SS, SNS>
where
    ES: EventStoreBackend<EventType = PolicyEvent> + Send + Sync + Clone + 'static,
    SS: StateStoreBackend<PolicyState> + Send + Sync + Clone,
    SNS: SnapshotStore<PolicyState> + Send + Sync + Clone,
{
    type SnapshotStore = SNS;

    fn snapshot_store(&self) -> SNS {
        self.snapshot_store.clone()
    }

    fn snapshot_config(&self) -> &SnapshotConfig {
        &self.snapshot_config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Association, ObjectAttribute, PolicyClass, PolicyView, UserAttribute};

    use epoch_mem::{
        InMemoryEventBus, InMemoryEventStore, InMemorySnapshotStore, InMemoryStateStore,
    };
    use tokio_stream::StreamExt;

    // =========================================================
    // POLICY_AGGREGATE_ID tests
    // =========================================================

    #[test]
    fn policy_aggregate_id_is_valid_uuid() {
        assert!(!POLICY_AGGREGATE_ID.is_nil());
    }

    #[test]
    fn policy_aggregate_id_is_stable() {
        let id1 = POLICY_AGGREGATE_ID;
        let id2 = POLICY_AGGREGATE_ID;
        assert_eq!(id1, id2);
    }

    // =========================================================
    // PolicyActor tests
    // =========================================================

    #[test]
    fn policy_actor_construction() {
        let id = Uuid::new_v4();
        let actor = PolicyActor { id };
        assert_eq!(actor.id, id);
    }

    #[test]
    fn policy_actor_clone() {
        let actor = PolicyActor { id: Uuid::new_v4() };
        let cloned = actor.clone();
        assert_eq!(actor.id, cloned.id);
    }

    #[test]
    fn policy_actor_debug() {
        let actor = PolicyActor { id: Uuid::new_v4() };
        let debug = format!("{:?}", actor);
        assert!(debug.contains("PolicyActor"));
    }

    // =========================================================
    // PolicyCommand tests
    // =========================================================

    #[test]
    fn policy_command_serde_roundtrip_create_ua() {
        let cmd = PolicyCommand::CreateUserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let deserialized: PolicyCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(json, serde_json::to_string(&deserialized).unwrap());
    }

    #[test]
    fn policy_command_serde_roundtrip_create_oa() {
        let cmd = PolicyCommand::CreateObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let deserialized: PolicyCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(json, serde_json::to_string(&deserialized).unwrap());
    }

    #[test]
    fn policy_command_serde_roundtrip_create_association() {
        let cmd = PolicyCommand::CreateAssociation {
            ua_id: Uuid::new_v4(),
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::from(["read".to_string(), "write".to_string()]),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let _deserialized: PolicyCommand = serde_json::from_str(&json).unwrap();
    }

    #[test]
    #[allow(clippy::useless_conversion)]
    fn policy_command_try_from_identity() {
        let id = Uuid::new_v4();
        let cmd = PolicyCommand::CreatePolicyClass {
            id,
            name: "platform".to_string(),
        };
        let result = PolicyCommand::try_from(cmd);
        assert!(result.is_ok());
        if let Ok(PolicyCommand::CreatePolicyClass { id: got_id, name }) = result {
            assert_eq!(got_id, id);
            assert_eq!(name, "platform");
        } else {
            panic!("unexpected variant");
        }
    }

    #[test]
    fn policy_command_all_variants_constructible() {
        let id = Uuid::new_v4();
        let _ = PolicyCommand::CreateUserAttribute {
            id,
            name: "test".to_string(),
            matcher: AttributeMatcher::All,
        };
        let _ = PolicyCommand::CreateObjectAttribute {
            id,
            name: "test".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let _ = PolicyCommand::CreatePolicyClass {
            id,
            name: "test".to_string(),
        };
        let _ = PolicyCommand::CreateAssociation {
            ua_id: id,
            target: AssociationTarget::ObjectAttribute(id),
            operations: HashSet::new(),
        };
        let _ = PolicyCommand::RemoveAssociation {
            ua_id: id,
            target: AssociationTarget::ObjectAttribute(id),
        };
        let _ = PolicyCommand::AssignOaToPc {
            oa_id: id,
            pc_id: id,
        };
        let _ = PolicyCommand::UnassignOaFromPc {
            oa_id: id,
            pc_id: id,
        };
    }

    // =========================================================
    // PolicyEvent tests
    // =========================================================

    #[test]
    fn policy_event_event_type_returns_variant_name() {
        let event = PolicyEvent::UserAttributeCreated {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        assert_eq!(event.event_type(), "UserAttributeCreated");

        let event = PolicyEvent::ObjectAttributeCreated {
            id: Uuid::new_v4(),
            name: "jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        assert_eq!(event.event_type(), "ObjectAttributeCreated");

        let event = PolicyEvent::PolicyClassCreated {
            id: Uuid::new_v4(),
            name: "platform".to_string(),
        };
        assert_eq!(event.event_type(), "PolicyClassCreated");

        let event = PolicyEvent::AssociationCreated {
            ua_id: Uuid::new_v4(),
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::from(["read".to_string()]),
        };
        assert_eq!(event.event_type(), "AssociationCreated");

        let event = PolicyEvent::AssociationRemoved {
            ua_id: Uuid::new_v4(),
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
        };
        assert_eq!(event.event_type(), "AssociationRemoved");

        let event = PolicyEvent::OaAssignedToPc {
            oa_id: Uuid::new_v4(),
            pc_id: Uuid::new_v4(),
        };
        assert_eq!(event.event_type(), "OaAssignedToPc");

        let event = PolicyEvent::OaUnassignedFromPc {
            oa_id: Uuid::new_v4(),
            pc_id: Uuid::new_v4(),
        };
        assert_eq!(event.event_type(), "OaUnassignedFromPc");
    }

    #[test]
    fn policy_event_try_from_ref_identity() {
        let event = PolicyEvent::PolicyClassCreated {
            id: Uuid::new_v4(),
            name: "test".to_string(),
        };
        let result = PolicyEvent::try_from(&event);
        assert!(result.is_ok());
    }

    #[test]
    fn policy_event_serde_roundtrip() {
        let event = PolicyEvent::ObjectAttributeCreated {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PolicyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(json, serde_json::to_string(&deserialized).unwrap());
    }

    #[test]
    fn policy_event_into_builder_sets_event_type() {
        let event = PolicyEvent::UserAttributeCreated {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let builder: EventBuilder<PolicyEvent> = event.into_builder();
        let built = builder.stream_id(POLICY_AGGREGATE_ID).build().unwrap();
        assert_eq!(built.event_type, "UserAttributeCreated");
        assert_eq!(built.stream_id, POLICY_AGGREGATE_ID);
    }

    // =========================================================
    // PolicyState tests
    // =========================================================

    #[test]
    fn policy_state_get_id_returns_aggregate_id() {
        let state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        assert_eq!(state.get_id(), &POLICY_AGGREGATE_ID);
    }

    #[test]
    fn policy_state_version_get_set() {
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        assert_eq!(state.get_version(), 0);
        state.set_version(42);
        assert_eq!(state.get_version(), 42);
    }

    #[test]
    fn policy_state_graph_is_accessible() {
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_pc(PolicyClass {
            id: Uuid::new_v4(),
            name: "test".to_string(),
        });
        assert_eq!(state.graph.policy_classes.len(), 1);
    }

    #[test]
    fn policy_state_clone() {
        let state = PolicyState {
            graph: PolicyGraph::new(),
            version: 5,
        };
        let cloned = state.clone();
        assert_eq!(cloned.get_version(), 5);
        assert_eq!(cloned.get_id(), &POLICY_AGGREGATE_ID);
    }

    #[test]
    fn policy_state_serde_roundtrip() {
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 3,
        };
        state.graph.add_ua(UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        });
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: PolicyState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.get_version(), 3);
        assert_eq!(
            deserialized
                .graph
                .matching_uas(&std::collections::HashMap::new())
                .len(),
            1
        );
    }

    // =========================================================
    // Error enum tests
    // =========================================================

    #[test]
    fn policy_command_error_display_ua_not_found() {
        let id = Uuid::new_v4();
        let err = PolicyCommandError::UserAttributeNotFound(id);
        assert_eq!(format!("{err}"), format!("User attribute {id} not found"));
    }

    #[test]
    fn policy_command_error_display_oa_not_found() {
        let id = Uuid::new_v4();
        let err = PolicyCommandError::ObjectAttributeNotFound(id);
        assert_eq!(format!("{err}"), format!("Object attribute {id} not found"));
    }

    #[test]
    fn policy_command_error_display_pc_not_found() {
        let id = Uuid::new_v4();
        let err = PolicyCommandError::PolicyClassNotFound(id);
        assert_eq!(format!("{err}"), format!("Policy class {id} not found"));
    }

    #[test]
    fn policy_command_error_from_event_builder_error() {
        let builder_err = EventBuilderError::StreamIdMissing;
        let err = PolicyCommandError::from(builder_err);
        let display = format!("{err}");
        assert!(display.contains("Error building event"));
    }

    // =========================================================
    // PolicyAggregate construction tests
    // =========================================================

    #[tokio::test]
    async fn policy_aggregate_new_compiles_with_in_memory_backends() {
        let bus = InMemoryEventBus::<PolicyEvent>::new();
        let event_store = InMemoryEventStore::new(bus);
        let state_store = InMemoryStateStore::<PolicyState>::new();
        let snapshot_store = InMemorySnapshotStore::<PolicyState>::new();
        let _aggregate = PolicyAggregate::new(event_store, state_store, snapshot_store);
    }

    #[tokio::test]
    async fn snapshot_captured_at_configured_interval() {
        let bus = InMemoryEventBus::<PolicyEvent>::new();
        let event_store = InMemoryEventStore::new(bus);
        let state_store = InMemoryStateStore::<PolicyState>::new();
        let snapshot_store = InMemorySnapshotStore::<PolicyState>::new();
        let agg = PolicyAggregate::new(event_store, state_store, snapshot_store.clone())
            .with_snapshot_config(SnapshotConfig {
                trigger: SnapshotTrigger::Automatic { interval: 3 },
                retention: SnapshotRetention::KeepLast(5),
            });

        // Two commands (versions 1, 2): no interval-3 boundary crossed yet.
        for i in 0..2 {
            agg.handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreateUserAttribute {
                    id: Uuid::new_v4(),
                    name: format!("ua{i}"),
                    matcher: AttributeMatcher::All,
                },
                Some(PolicyActor { id: Uuid::new_v4() }),
                None,
            ))
            .await
            .unwrap();
        }
        assert!(
            snapshot_store
                .load_snapshot(POLICY_AGGREGATE_ID, 2)
                .await
                .unwrap()
                .is_none(),
            "no snapshot before crossing the interval boundary"
        );

        // Third command (version 3) crosses the interval-3 boundary: capture.
        agg.handle(Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreateUserAttribute {
                id: Uuid::new_v4(),
                name: "ua2".to_string(),
                matcher: AttributeMatcher::All,
            },
            Some(PolicyActor { id: Uuid::new_v4() }),
            None,
        ))
        .await
        .unwrap();

        let snap = snapshot_store
            .load_snapshot(POLICY_AGGREGATE_ID, 3)
            .await
            .unwrap()
            .expect("snapshot captured at the interval boundary");
        assert_eq!(snap.version, 3);
        assert_eq!(snap.state.graph.user_attributes.len(), 3);
    }

    // =========================================================
    // EventApplicator test helpers
    // =========================================================

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

    /// Build an `Event<PolicyEvent>` with the given data for use in `apply` tests.
    fn make_event(data: PolicyEvent) -> Event<PolicyEvent> {
        data.into_builder()
            .stream_id(POLICY_AGGREGATE_ID)
            .build()
            .unwrap()
    }

    // =========================================================
    // EventApplicator::apply tests
    // =========================================================

    #[tokio::test]
    async fn apply_user_attribute_created_on_none_state() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let event = make_event(PolicyEvent::UserAttributeCreated {
            id,
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        });
        let result = agg.apply(None, &event);
        assert!(result.is_ok());
        let state = result.unwrap().unwrap();
        let uas = state.graph.matching_uas(&std::collections::HashMap::new());
        assert_eq!(uas.len(), 1);
        assert_eq!(uas[0].id, id);
        assert_eq!(uas[0].name, "admins");
    }

    #[tokio::test]
    async fn apply_user_attribute_created_on_existing_state() {
        let agg = make_aggregate();
        let existing_state = PolicyState {
            graph: PolicyGraph::new(),
            version: 5,
        };
        let id = Uuid::new_v4();
        let event = make_event(PolicyEvent::UserAttributeCreated {
            id,
            name: "editors".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "role".to_string(),
                values: vec!["editor".to_string()],
            },
        });
        let result = agg.apply(Some(existing_state), &event);
        assert!(result.is_ok());
        let state = result.unwrap().unwrap();
        assert_eq!(state.version, 5);
        let uas = state.graph.matching_uas(&std::collections::HashMap::from([(
            "role".to_string(),
            std::collections::HashSet::from(["editor".to_string()]),
        )]));
        assert_eq!(uas.len(), 1);
        assert_eq!(uas[0].id, id);
    }

    #[tokio::test]
    async fn apply_object_attribute_created() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let event = make_event(PolicyEvent::ObjectAttributeCreated {
            id,
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        });
        let state = agg.apply(None, &event).unwrap().unwrap();
        let oa = state.graph.get_oa(id);
        assert!(oa.is_some());
        let oa = oa.unwrap();
        assert_eq!(oa.name, "alpha_jobs");
        assert_eq!(oa.resource_type, "job");
    }

    #[tokio::test]
    async fn apply_policy_class_created() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let event = make_event(PolicyEvent::PolicyClassCreated {
            id,
            name: "platform_policy".to_string(),
        });
        let state = agg.apply(None, &event).unwrap().unwrap();
        assert!(state.graph.policy_classes.contains_key(&id));
        assert_eq!(state.graph.policy_classes[&id].name, "platform_policy");
    }

    #[tokio::test]
    async fn apply_association_created() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();

        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_ua(UserAttribute {
            id: ua_id,
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        });

        let event = make_event(PolicyEvent::AssociationCreated {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string(), "write".to_string()]),
        });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        let assocs = state.graph.associations_for_ua(ua_id);
        assert_eq!(assocs.len(), 1);
        assert_eq!(assocs[0].target, AssociationTarget::ObjectAttribute(oa_id));
        assert!(assocs[0].operations.contains("read"));
        assert!(assocs[0].operations.contains("write"));
    }

    #[tokio::test]
    async fn apply_association_removed() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();

        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });

        let event = make_event(PolicyEvent::AssociationRemoved {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
        });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        assert!(state.graph.associations_for_ua(ua_id).is_empty());
    }

    #[tokio::test]
    async fn apply_oa_assigned_to_pc() {
        let agg = make_aggregate();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();

        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_oa(ObjectAttribute {
            id: oa_id,
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        state.graph.add_pc(PolicyClass {
            id: pc_id,
            name: "platform".to_string(),
        });

        let event = make_event(PolicyEvent::OaAssignedToPc { oa_id, pc_id });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        let oas = state.graph.oas_for_pc(pc_id, "job");
        assert_eq!(oas.len(), 1);
        assert_eq!(oas[0].id, oa_id);
    }

    #[tokio::test]
    async fn apply_oa_unassigned_from_pc() {
        let agg = make_aggregate();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();

        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_oa(ObjectAttribute {
            id: oa_id,
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        state.graph.add_pc(PolicyClass {
            id: pc_id,
            name: "platform".to_string(),
        });
        state.graph.assign_oa_to_pc(oa_id, pc_id);

        let event = make_event(PolicyEvent::OaUnassignedFromPc { oa_id, pc_id });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        assert!(state.graph.oas_for_pc(pc_id, "job").is_empty());
    }

    #[tokio::test]
    async fn apply_always_returns_some() {
        let agg = make_aggregate();
        let event = make_event(PolicyEvent::PolicyClassCreated {
            id: Uuid::new_v4(),
            name: "test".to_string(),
        });
        let result = agg.apply(None, &event).unwrap();
        assert!(result.is_some(), "apply should always return Some(state)");
    }

    #[tokio::test]
    async fn apply_none_state_initializes_empty_graph() {
        let agg = make_aggregate();
        let pc_id = Uuid::new_v4();
        let event = make_event(PolicyEvent::PolicyClassCreated {
            id: pc_id,
            name: "test".to_string(),
        });
        let state = agg.apply(None, &event).unwrap().unwrap();
        assert_eq!(state.graph.policy_classes.len(), 1);
        assert!(state.graph.user_attributes.is_empty());
        assert!(state.graph.object_attributes.is_empty());
        assert!(state.graph.associations_for_ua(Uuid::new_v4()).is_empty());
    }

    #[tokio::test]
    async fn apply_sequential_events_accumulate_in_graph() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();

        let e1 = make_event(PolicyEvent::UserAttributeCreated {
            id: ua_id,
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        });
        let e2 = make_event(PolicyEvent::ObjectAttributeCreated {
            id: oa_id,
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        let e3 = make_event(PolicyEvent::PolicyClassCreated {
            id: pc_id,
            name: "platform".to_string(),
        });

        let state = agg.apply(None, &e1).unwrap();
        let state = agg.apply(state, &e2).unwrap();
        let state = agg.apply(state, &e3).unwrap().unwrap();

        assert_eq!(state.graph.user_attributes.len(), 1);
        assert_eq!(state.graph.object_attributes.len(), 1);
        assert_eq!(state.graph.policy_classes.len(), 1);
        assert!(
            state
                .graph
                .matching_uas(&std::collections::HashMap::new())
                .len()
                == 1
        );
        assert!(state.graph.get_oa(oa_id).is_some());
    }

    #[tokio::test]
    async fn get_state_store_returns_clone_of_store() {
        let agg = make_aggregate();
        let _store: InMemoryStateStore<PolicyState> = agg.get_state_store();
    }

    #[tokio::test]
    async fn get_event_store_returns_clone_of_store() {
        let agg = make_aggregate();
        let _store: InMemoryEventStore<InMemoryEventBus<PolicyEvent>> = agg.get_event_store();
    }

    // =========================================================
    // Aggregate::handle_command test helpers
    // =========================================================

    /// Build a `Command<PolicyCommand, PolicyActor>` with a test actor.
    fn cmd(data: PolicyCommand) -> Command<PolicyCommand, PolicyActor> {
        Command::new(
            POLICY_AGGREGATE_ID,
            data,
            Some(PolicyActor { id: Uuid::new_v4() }),
            None,
        )
    }

    /// Build a `Command<PolicyCommand, PolicyActor>` with a specific actor ID.
    fn cmd_with_actor(data: PolicyCommand, actor_id: Uuid) -> Command<PolicyCommand, PolicyActor> {
        Command::new(
            POLICY_AGGREGATE_ID,
            data,
            Some(PolicyActor { id: actor_id }),
            None,
        )
    }

    /// Helper: build a state with a UA, OA, and PC pre-populated.
    fn state_with_ua_oa_pc(ua_id: Uuid, oa_id: Uuid, pc_id: Uuid) -> Option<PolicyState> {
        let mut graph = PolicyGraph::new();
        graph.add_ua(UserAttribute {
            id: ua_id,
            name: "test_ua".to_string(),
            matcher: AttributeMatcher::All,
        });
        graph.add_oa(ObjectAttribute {
            id: oa_id,
            name: "test_oa".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        graph.add_pc(PolicyClass {
            id: pc_id,
            name: "test_pc".to_string(),
        });
        Some(PolicyState { graph, version: 1 })
    }

    // =========================================================
    // Aggregate::handle_command — creation commands
    // =========================================================

    #[tokio::test]
    async fn handle_create_ua_against_none_state_produces_event() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let command = cmd(PolicyCommand::CreateUserAttribute {
            id,
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        });
        let events = agg.handle_command(&None, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "UserAttributeCreated");
        assert_eq!(events[0].stream_id, POLICY_AGGREGATE_ID);
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::UserAttributeCreated {
                id: eid,
                name,
                matcher,
            } => {
                assert_eq!(*eid, id);
                assert_eq!(name, "admins");
                assert_eq!(*matcher, AttributeMatcher::All);
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn handle_create_oa_against_none_state_produces_event() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let command = cmd(PolicyCommand::CreateObjectAttribute {
            id,
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        });
        let events = agg.handle_command(&None, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "ObjectAttributeCreated");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::ObjectAttributeCreated {
                id: eid,
                name,
                resource_type,
                ..
            } => {
                assert_eq!(*eid, id);
                assert_eq!(name, "alpha_jobs");
                assert_eq!(resource_type, "job");
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn handle_create_pc_against_none_state_produces_event() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let command = cmd(PolicyCommand::CreatePolicyClass {
            id,
            name: "platform".to_string(),
        });
        let events = agg.handle_command(&None, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "PolicyClassCreated");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::PolicyClassCreated { id: eid, name } => {
                assert_eq!(*eid, id);
                assert_eq!(name, "platform");
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn handle_create_ua_against_existing_state_produces_event() {
        let agg = make_aggregate();
        let state = Some(PolicyState {
            graph: PolicyGraph::new(),
            version: 3,
        });
        let id = Uuid::new_v4();
        let command = cmd(PolicyCommand::CreateUserAttribute {
            id,
            name: "editors".to_string(),
            matcher: AttributeMatcher::All,
        });
        let events = agg.handle_command(&state, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "UserAttributeCreated");
    }

    #[tokio::test]
    async fn handle_create_multiple_nodes_accumulate_in_graph() {
        let agg = make_aggregate();
        let actor = Some(PolicyActor { id: Uuid::new_v4() });
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();

        // Create UA
        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreateUserAttribute {
                    id: ua_id,
                    name: "admins".to_string(),
                    matcher: AttributeMatcher::All,
                },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.graph.user_attributes.len(), 1);
        assert_eq!(state.graph.object_attributes.len(), 0);
        assert_eq!(state.graph.policy_classes.len(), 0);

        // Create OA
        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreateObjectAttribute {
                    id: oa_id,
                    name: "alpha_jobs".to_string(),
                    resource_type: "job".to_string(),
                    matcher: AttributeMatcher::All,
                },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.graph.user_attributes.len(), 1);
        assert_eq!(state.graph.object_attributes.len(), 1);
        assert_eq!(state.graph.policy_classes.len(), 0);

        // Create PC
        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreatePolicyClass {
                    id: pc_id,
                    name: "platform".to_string(),
                },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.graph.user_attributes.len(), 1);
        assert_eq!(state.graph.object_attributes.len(), 1);
        assert_eq!(state.graph.policy_classes.len(), 1);
    }

    // =========================================================
    // Aggregate::handle_command — association commands (happy path)
    // =========================================================

    #[tokio::test]
    async fn handle_create_association_with_oa_target_succeeds() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let state = state_with_ua_oa_pc(ua_id, oa_id, pc_id);

        let command = cmd(PolicyCommand::CreateAssociation {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string(), "write".to_string()]),
        });
        let events = agg.handle_command(&state, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "AssociationCreated");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::AssociationCreated {
                ua_id: eid,
                target,
                operations,
            } => {
                assert_eq!(*eid, ua_id);
                assert_eq!(*target, AssociationTarget::ObjectAttribute(oa_id));
                assert!(operations.contains("read"));
                assert!(operations.contains("write"));
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn handle_create_association_with_pc_target_succeeds() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let state = state_with_ua_oa_pc(ua_id, oa_id, pc_id);

        let command = cmd(PolicyCommand::CreateAssociation {
            ua_id,
            target: AssociationTarget::PolicyClass(pc_id),
            operations: HashSet::from(["admin".to_string()]),
        });
        let events = agg.handle_command(&state, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "AssociationCreated");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::AssociationCreated { target, .. } => {
                assert_eq!(*target, AssociationTarget::PolicyClass(pc_id));
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn handle_remove_association_succeeds() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let state = state_with_ua_oa_pc(ua_id, oa_id, pc_id);

        let command = cmd(PolicyCommand::RemoveAssociation {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
        });
        let events = agg.handle_command(&state, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "AssociationRemoved");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::AssociationRemoved { ua_id: eid, target } => {
                assert_eq!(*eid, ua_id);
                assert_eq!(*target, AssociationTarget::ObjectAttribute(oa_id));
            }
            _ => panic!("unexpected event variant"),
        }
    }

    // =========================================================
    // Aggregate::handle_command — association commands (error paths)
    // =========================================================

    #[tokio::test]
    async fn handle_create_association_against_none_state_returns_ua_not_found() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::CreateAssociation {
            ua_id,
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::from(["read".to_string()]),
        });
        let err = agg.handle_command(&None, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::UserAttributeNotFound(id) if id == ua_id),
            "expected UserAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_create_association_missing_ua_returns_error() {
        let agg = make_aggregate();
        let oa_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_oa(ObjectAttribute {
            id: oa_id,
            name: "test_oa".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_ua_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::CreateAssociation {
            ua_id: missing_ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::UserAttributeNotFound(id) if id == missing_ua_id),
            "expected UserAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_create_association_missing_oa_target_returns_error() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_ua(UserAttribute {
            id: ua_id,
            name: "test_ua".to_string(),
            matcher: AttributeMatcher::All,
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_oa_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::CreateAssociation {
            ua_id,
            target: AssociationTarget::ObjectAttribute(missing_oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::ObjectAttributeNotFound(id) if id == missing_oa_id),
            "expected ObjectAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_create_association_missing_pc_target_returns_error() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_ua(UserAttribute {
            id: ua_id,
            name: "test_ua".to_string(),
            matcher: AttributeMatcher::All,
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_pc_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::CreateAssociation {
            ua_id,
            target: AssociationTarget::PolicyClass(missing_pc_id),
            operations: HashSet::from(["read".to_string()]),
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::PolicyClassNotFound(id) if id == missing_pc_id),
            "expected PolicyClassNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_remove_association_against_none_state_returns_ua_not_found() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::RemoveAssociation {
            ua_id,
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
        });
        let err = agg.handle_command(&None, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::UserAttributeNotFound(id) if id == ua_id),
            "expected UserAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_remove_association_missing_ua_returns_error() {
        let agg = make_aggregate();
        let oa_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_oa(ObjectAttribute {
            id: oa_id,
            name: "test_oa".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_ua_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::RemoveAssociation {
            ua_id: missing_ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::UserAttributeNotFound(id) if id == missing_ua_id),
            "expected UserAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_remove_association_missing_oa_target_returns_error() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_ua(UserAttribute {
            id: ua_id,
            name: "test_ua".to_string(),
            matcher: AttributeMatcher::All,
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_oa_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::RemoveAssociation {
            ua_id,
            target: AssociationTarget::ObjectAttribute(missing_oa_id),
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::ObjectAttributeNotFound(id) if id == missing_oa_id),
            "expected ObjectAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_remove_association_missing_pc_target_returns_error() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_ua(UserAttribute {
            id: ua_id,
            name: "test_ua".to_string(),
            matcher: AttributeMatcher::All,
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_pc_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::RemoveAssociation {
            ua_id,
            target: AssociationTarget::PolicyClass(missing_pc_id),
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::PolicyClassNotFound(id) if id == missing_pc_id),
            "expected PolicyClassNotFound, got: {err:?}"
        );
    }

    // =========================================================
    // Aggregate::handle_command — OA→PC assignment commands
    // =========================================================

    #[tokio::test]
    async fn handle_assign_oa_to_pc_succeeds() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let state = state_with_ua_oa_pc(ua_id, oa_id, pc_id);

        let command = cmd(PolicyCommand::AssignOaToPc { oa_id, pc_id });
        let events = agg.handle_command(&state, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "OaAssignedToPc");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::OaAssignedToPc {
                oa_id: eid,
                pc_id: pid,
            } => {
                assert_eq!(*eid, oa_id);
                assert_eq!(*pid, pc_id);
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn handle_assign_oa_to_pc_missing_oa_returns_error() {
        let agg = make_aggregate();
        let pc_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_pc(PolicyClass {
            id: pc_id,
            name: "test_pc".to_string(),
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_oa_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::AssignOaToPc {
            oa_id: missing_oa_id,
            pc_id,
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::ObjectAttributeNotFound(id) if id == missing_oa_id),
            "expected ObjectAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_assign_oa_to_pc_missing_pc_returns_error() {
        let agg = make_aggregate();
        let oa_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_oa(ObjectAttribute {
            id: oa_id,
            name: "test_oa".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_pc_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::AssignOaToPc {
            oa_id,
            pc_id: missing_pc_id,
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::PolicyClassNotFound(id) if id == missing_pc_id),
            "expected PolicyClassNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_assign_oa_to_pc_against_none_state_returns_oa_not_found() {
        let agg = make_aggregate();
        let oa_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::AssignOaToPc {
            oa_id,
            pc_id: Uuid::new_v4(),
        });
        let err = agg.handle_command(&None, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::ObjectAttributeNotFound(id) if id == oa_id),
            "expected ObjectAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_unassign_oa_from_pc_succeeds() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let state = state_with_ua_oa_pc(ua_id, oa_id, pc_id);

        let command = cmd(PolicyCommand::UnassignOaFromPc { oa_id, pc_id });
        let events = agg.handle_command(&state, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "OaUnassignedFromPc");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::OaUnassignedFromPc {
                oa_id: eid,
                pc_id: pid,
            } => {
                assert_eq!(*eid, oa_id);
                assert_eq!(*pid, pc_id);
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn handle_unassign_oa_from_pc_missing_oa_returns_error() {
        let agg = make_aggregate();
        let pc_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_pc(PolicyClass {
            id: pc_id,
            name: "test_pc".to_string(),
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_oa_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::UnassignOaFromPc {
            oa_id: missing_oa_id,
            pc_id,
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::ObjectAttributeNotFound(id) if id == missing_oa_id),
            "expected ObjectAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_unassign_oa_from_pc_missing_pc_returns_error() {
        let agg = make_aggregate();
        let oa_id = Uuid::new_v4();
        let mut graph = PolicyGraph::new();
        graph.add_oa(ObjectAttribute {
            id: oa_id,
            name: "test_oa".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        let state = Some(PolicyState { graph, version: 1 });

        let missing_pc_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::UnassignOaFromPc {
            oa_id,
            pc_id: missing_pc_id,
        });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::PolicyClassNotFound(id) if id == missing_pc_id),
            "expected PolicyClassNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_unassign_oa_from_pc_against_none_state_returns_oa_not_found() {
        let agg = make_aggregate();
        let oa_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::UnassignOaFromPc {
            oa_id,
            pc_id: Uuid::new_v4(),
        });
        let err = agg.handle_command(&None, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::ObjectAttributeNotFound(id) if id == oa_id),
            "expected ObjectAttributeNotFound, got: {err:?}"
        );
    }

    // =========================================================
    // Aggregate::handle_command — actor ID audit tests
    // =========================================================

    #[tokio::test]
    async fn events_carry_actor_id_from_credentials() {
        let agg = make_aggregate();
        let actor_id = Uuid::new_v4();
        let command = cmd_with_actor(
            PolicyCommand::CreatePolicyClass {
                id: Uuid::new_v4(),
                name: "test".to_string(),
            },
            actor_id,
        );
        let events = agg.handle_command(&None, command).await.unwrap();
        assert_eq!(events[0].actor_id, Some(actor_id));
    }

    #[tokio::test]
    async fn events_have_none_actor_id_when_no_credentials() {
        let agg = make_aggregate();
        let command = Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreatePolicyClass {
                id: Uuid::new_v4(),
                name: "test".to_string(),
            },
            None::<PolicyActor>,
            None,
        );
        let events = agg.handle_command(&None, command).await.unwrap();
        assert_eq!(events[0].actor_id, None);
    }

    // =========================================================
    // Aggregate round-trip tests (using full handle() flow)
    // =========================================================

    #[tokio::test]
    async fn aggregate_round_trip_graph_queryable() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        // Create UA
        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreateUserAttribute {
                    id: ua_id,
                    name: "admins".to_string(),
                    matcher: AttributeMatcher::All,
                },
                Some(PolicyActor { id: actor_id }),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            state
                .graph
                .matching_uas(&std::collections::HashMap::new())
                .len(),
            1
        );

        // Create OA
        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreateObjectAttribute {
                    id: oa_id,
                    name: "alpha_jobs".to_string(),
                    resource_type: "job".to_string(),
                    matcher: AttributeMatcher::Matching {
                        key: "org_id".to_string(),
                        values: vec!["alpha".to_string()],
                    },
                },
                Some(PolicyActor { id: actor_id }),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert!(state.graph.get_oa(oa_id).is_some());

        // Create PC
        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreatePolicyClass {
                    id: pc_id,
                    name: "platform".to_string(),
                },
                Some(PolicyActor { id: actor_id }),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.graph.policy_classes.len(), 1);

        // Assign OA→PC
        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::AssignOaToPc { oa_id, pc_id },
                Some(PolicyActor { id: actor_id }),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.graph.oas_for_pc(pc_id, "job").len(), 1);

        // Create association
        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreateAssociation {
                    ua_id,
                    target: AssociationTarget::ObjectAttribute(oa_id),
                    operations: HashSet::from(["read".to_string(), "write".to_string()]),
                },
                Some(PolicyActor { id: actor_id }),
                None,
            ))
            .await
            .unwrap()
            .unwrap();

        // Verify the full graph is queryable
        let uas = state.graph.matching_uas(&std::collections::HashMap::new());
        assert_eq!(uas.len(), 1);
        assert_eq!(uas[0].id, ua_id);

        let assocs = state.graph.associations_for_ua(ua_id);
        assert_eq!(assocs.len(), 1);
        assert!(assocs[0].operations.contains("read"));
        assert!(assocs[0].operations.contains("write"));

        let oas = state.graph.oas_for_pc(pc_id, "job");
        assert_eq!(oas.len(), 1);
        assert_eq!(oas[0].id, oa_id);
    }

    #[tokio::test]
    async fn aggregate_events_persisted_in_event_store() {
        let agg = make_aggregate();
        let actor = Some(PolicyActor { id: Uuid::new_v4() });

        agg.handle(Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreateUserAttribute {
                id: Uuid::new_v4(),
                name: "ua1".to_string(),
                matcher: AttributeMatcher::All,
            },
            actor.clone(),
            None,
        ))
        .await
        .unwrap();

        agg.handle(Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreateObjectAttribute {
                id: Uuid::new_v4(),
                name: "oa1".to_string(),
                resource_type: "job".to_string(),
                matcher: AttributeMatcher::All,
            },
            actor.clone(),
            None,
        ))
        .await
        .unwrap();

        agg.handle(Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreatePolicyClass {
                id: Uuid::new_v4(),
                name: "pc1".to_string(),
            },
            actor.clone(),
            None,
        ))
        .await
        .unwrap();

        // Read events back from event store
        let store = agg.get_event_store();
        let stream = store.read_events(POLICY_AGGREGATE_ID).await.unwrap();
        let events: Vec<_> = stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "UserAttributeCreated");
        assert_eq!(events[1].event_type, "ObjectAttributeCreated");
        assert_eq!(events[2].event_type, "PolicyClassCreated");
    }

    #[tokio::test]
    async fn aggregate_state_persisted_in_state_store() {
        let agg = make_aggregate();
        let actor = Some(PolicyActor { id: Uuid::new_v4() });
        let ua_id = Uuid::new_v4();

        agg.handle(Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreateUserAttribute {
                id: ua_id,
                name: "admins".to_string(),
                matcher: AttributeMatcher::All,
            },
            actor,
            None,
        ))
        .await
        .unwrap();

        // Read state back from state store
        let store = agg.get_state_store();
        let state = store.get_state(POLICY_AGGREGATE_ID).await.unwrap();
        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.get_version(), 1);
        assert_eq!(
            state
                .graph
                .matching_uas(&std::collections::HashMap::new())
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn policy_state_version_increments_per_command() {
        let agg = make_aggregate();
        let actor = Some(PolicyActor { id: Uuid::new_v4() });

        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreatePolicyClass {
                    id: Uuid::new_v4(),
                    name: "pc1".to_string(),
                },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.get_version(), 1);

        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreateUserAttribute {
                    id: Uuid::new_v4(),
                    name: "ua1".to_string(),
                    matcher: AttributeMatcher::All,
                },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.get_version(), 2);

        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::CreateObjectAttribute {
                    id: Uuid::new_v4(),
                    name: "oa1".to_string(),
                    resource_type: "job".to_string(),
                    matcher: AttributeMatcher::All,
                },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.get_version(), 3);
    }

    // =========================================================
    // REQ-HARD-002 — association upsert replay coherence
    // =========================================================

    /// Replaying `AssociationCreated` for the same `(ua_id, target)` pair
    /// upserts: exactly one association survives with the second event's
    /// operation set. A subsequent `AssociationRemoved` removes it cleanly,
    /// and sibling associations (different target) are unaffected.
    #[tokio::test]
    async fn apply_association_replay_coherence_upsert_and_remove() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_target = Uuid::new_v4();
        let oa_sibling = Uuid::new_v4();

        // Baseline state: sibling association on the same UA
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_sibling),
            operations: HashSet::from(["admin".to_string()]),
        });

        // Event 1: create (ua_id, oa_target) with {read}
        let ev1 = make_event(PolicyEvent::AssociationCreated {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_target),
            operations: HashSet::from(["read".to_string()]),
        });
        let state1 = agg.apply(Some(state), &ev1).unwrap().unwrap();
        let assocs1 = state1.graph.associations_for_ua(ua_id);
        // Two total: sibling + new
        assert_eq!(assocs1.len(), 2);

        // Event 2: upsert (ua_id, oa_target) with {write, delete}
        let ev2 = make_event(PolicyEvent::AssociationCreated {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_target),
            operations: HashSet::from(["write".to_string(), "delete".to_string()]),
        });
        let state2 = agg.apply(Some(state1), &ev2).unwrap().unwrap();
        let assocs2 = state2.graph.associations_for_ua(ua_id);
        // Still two total (upsert replaced, not appended)
        assert_eq!(assocs2.len(), 2);
        // The oa_target association now has {write, delete}
        let target_assoc = assocs2
            .iter()
            .find(|a| a.target == AssociationTarget::ObjectAttribute(oa_target))
            .expect("target association must exist");
        assert!(target_assoc.operations.contains("write"));
        assert!(target_assoc.operations.contains("delete"));
        assert!(!target_assoc.operations.contains("read"));
        // Sibling is untouched
        let sibling = assocs2
            .iter()
            .find(|a| a.target == AssociationTarget::ObjectAttribute(oa_sibling))
            .expect("sibling association must exist");
        assert!(sibling.operations.contains("admin"));

        // Event 3: remove (ua_id, oa_target)
        let ev3 = make_event(PolicyEvent::AssociationRemoved {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_target),
        });
        let state3 = agg.apply(Some(state2), &ev3).unwrap().unwrap();
        let assocs3 = state3.graph.associations_for_ua(ua_id);
        // Only sibling remains
        assert_eq!(assocs3.len(), 1);
        assert_eq!(
            assocs3[0].target,
            AssociationTarget::ObjectAttribute(oa_sibling)
        );
    }

    // =========================================================
    // REQ-HARD-003 — apply returns MissingEventData for purged events
    // =========================================================

    /// `apply` with an event whose `data` is `None` (purged event) must
    /// return `Err(PolicyApplyError::MissingEventData(event.id))` — no panic.
    #[tokio::test]
    async fn apply_data_none_returns_missing_event_data_error() {
        let agg = make_aggregate();
        // Build a normal event, then simulate purging by setting data to None
        let base = make_event(PolicyEvent::PolicyClassCreated {
            id: Uuid::new_v4(),
            name: "test_pc".to_string(),
        });
        let event_id = base.id;
        let purged = Event { data: None, ..base };
        let result = agg.apply(None, &purged);
        assert!(
            matches!(result, Err(PolicyApplyError::MissingEventData(id)) if id == event_id),
            "expected MissingEventData({event_id}), got {result:?}"
        );
    }

    #[test]
    fn policy_command_delete_ua_serde_roundtrip() {
        let cmd = PolicyCommand::DeleteUserAttribute { id: Uuid::new_v4() };
        let json = serde_json::to_string(&cmd).unwrap();
        let deserialized: PolicyCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(json, serde_json::to_string(&deserialized).unwrap());
    }

    #[test]
    fn policy_command_delete_oa_serde_roundtrip() {
        let cmd = PolicyCommand::DeleteObjectAttribute { id: Uuid::new_v4() };
        let json = serde_json::to_string(&cmd).unwrap();
        let deserialized: PolicyCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(json, serde_json::to_string(&deserialized).unwrap());
    }

    #[test]
    fn policy_command_delete_pc_serde_roundtrip() {
        let cmd = PolicyCommand::DeletePolicyClass { id: Uuid::new_v4() };
        let json = serde_json::to_string(&cmd).unwrap();
        let deserialized: PolicyCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(json, serde_json::to_string(&deserialized).unwrap());
    }

    // =========================================================
    // PolicyEvent — deleted variants
    // =========================================================

    #[test]
    fn policy_event_deleted_variants_event_type() {
        let id = Uuid::new_v4();
        let ua_event = PolicyEvent::UserAttributeDeleted { id };
        assert_eq!(ua_event.event_type(), "UserAttributeDeleted");
        let oa_event = PolicyEvent::ObjectAttributeDeleted { id };
        assert_eq!(oa_event.event_type(), "ObjectAttributeDeleted");
        let pc_event = PolicyEvent::PolicyClassDeleted { id };
        assert_eq!(pc_event.event_type(), "PolicyClassDeleted");
    }

    #[test]
    fn policy_event_deleted_variants_serde_roundtrip() {
        let id = Uuid::new_v4();
        for event in [
            PolicyEvent::UserAttributeDeleted { id },
            PolicyEvent::ObjectAttributeDeleted { id },
            PolicyEvent::PolicyClassDeleted { id },
        ] {
            let json = serde_json::to_string(&event).unwrap();
            let deserialized: PolicyEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(json, serde_json::to_string(&deserialized).unwrap());
        }
    }

    // =========================================================
    // EventApplicator::apply — delete events
    // =========================================================

    #[tokio::test]
    async fn apply_user_attribute_deleted_removes_ua() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_ua(UserAttribute {
            id,
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        });
        assert!(state.graph.user_attributes.contains_key(&id));

        let event = make_event(PolicyEvent::UserAttributeDeleted { id });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        assert!(!state.graph.user_attributes.contains_key(&id));
    }

    #[tokio::test]
    async fn apply_user_attribute_deleted_cascades_associations() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_ua(UserAttribute {
            id: ua_id,
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        });
        state.graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        assert_eq!(state.graph.associations_for_ua(ua_id).len(), 1);

        let event = make_event(PolicyEvent::UserAttributeDeleted { id: ua_id });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        assert!(state.graph.associations_for_ua(ua_id).is_empty());
    }

    #[tokio::test]
    async fn apply_object_attribute_deleted_removes_oa() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_oa(ObjectAttribute {
            id,
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        assert!(state.graph.object_attributes.contains_key(&id));

        let event = make_event(PolicyEvent::ObjectAttributeDeleted { id });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        assert!(!state.graph.object_attributes.contains_key(&id));
    }

    #[tokio::test]
    async fn apply_object_attribute_deleted_cascades_associations_and_assignments() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_ua(UserAttribute {
            id: ua_id,
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        });
        state.graph.add_oa(ObjectAttribute {
            id: oa_id,
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        state.graph.add_pc(PolicyClass {
            id: pc_id,
            name: "platform".to_string(),
        });
        state.graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        state.graph.assign_oa_to_pc(oa_id, pc_id);

        let event = make_event(PolicyEvent::ObjectAttributeDeleted { id: oa_id });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        assert!(!state.graph.object_attributes.contains_key(&oa_id));
        assert!(state.graph.associations_for_ua(ua_id).is_empty());
        assert!(state.graph.oas_for_pc(pc_id, "job").is_empty());
    }

    #[tokio::test]
    async fn apply_policy_class_deleted_removes_pc() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_pc(PolicyClass {
            id,
            name: "platform".to_string(),
        });
        assert!(state.graph.policy_classes.contains_key(&id));

        let event = make_event(PolicyEvent::PolicyClassDeleted { id });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        assert!(!state.graph.policy_classes.contains_key(&id));
    }

    #[tokio::test]
    async fn apply_policy_class_deleted_cascades_associations_and_assignments() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let mut state = PolicyState {
            graph: PolicyGraph::new(),
            version: 0,
        };
        state.graph.add_ua(UserAttribute {
            id: ua_id,
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        });
        state.graph.add_oa(ObjectAttribute {
            id: oa_id,
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        });
        state.graph.add_pc(PolicyClass {
            id: pc_id,
            name: "platform".to_string(),
        });
        state.graph.add_association(Association {
            ua_id,
            target: AssociationTarget::PolicyClass(pc_id),
            operations: HashSet::from(["admin".to_string()]),
        });
        state.graph.assign_oa_to_pc(oa_id, pc_id);

        let event = make_event(PolicyEvent::PolicyClassDeleted { id: pc_id });
        let state = agg.apply(Some(state), &event).unwrap().unwrap();
        assert!(!state.graph.policy_classes.contains_key(&pc_id));
        // Association targeting the PC is removed
        assert!(state.graph.associations_for_ua(ua_id).is_empty());
        // OA→PC assignment is removed; OA itself still exists
        assert!(state.graph.object_attributes.contains_key(&oa_id));
        assert!(state.graph.oas_for_pc(pc_id, "job").is_empty());
    }

    // =========================================================
    // handle_command — delete commands (happy path)
    // =========================================================

    #[tokio::test]
    async fn handle_delete_ua_produces_event() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let state = state_with_ua_oa_pc(ua_id, oa_id, pc_id);

        let command = cmd(PolicyCommand::DeleteUserAttribute { id: ua_id });
        let events = agg.handle_command(&state, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "UserAttributeDeleted");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::UserAttributeDeleted { id } => assert_eq!(*id, ua_id),
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn handle_delete_oa_produces_event() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let state = state_with_ua_oa_pc(ua_id, oa_id, pc_id);

        let command = cmd(PolicyCommand::DeleteObjectAttribute { id: oa_id });
        let events = agg.handle_command(&state, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "ObjectAttributeDeleted");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::ObjectAttributeDeleted { id } => assert_eq!(*id, oa_id),
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn handle_delete_pc_produces_event() {
        let agg = make_aggregate();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let state = state_with_ua_oa_pc(ua_id, oa_id, pc_id);

        let command = cmd(PolicyCommand::DeletePolicyClass { id: pc_id });
        let events = agg.handle_command(&state, command).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "PolicyClassDeleted");
        match events[0].data.as_ref().unwrap() {
            PolicyEvent::PolicyClassDeleted { id } => assert_eq!(*id, pc_id),
            _ => panic!("unexpected event variant"),
        }
    }

    // =========================================================
    // handle_command — delete commands (error paths)
    // =========================================================

    #[tokio::test]
    async fn handle_delete_ua_against_none_state_returns_not_found() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let command = cmd(PolicyCommand::DeleteUserAttribute { id });
        let err = agg.handle_command(&None, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::UserAttributeNotFound(eid) if eid == id),
            "expected UserAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_delete_oa_against_none_state_returns_not_found() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let command = cmd(PolicyCommand::DeleteObjectAttribute { id });
        let err = agg.handle_command(&None, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::ObjectAttributeNotFound(eid) if eid == id),
            "expected ObjectAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_delete_pc_against_none_state_returns_not_found() {
        let agg = make_aggregate();
        let id = Uuid::new_v4();
        let command = cmd(PolicyCommand::DeletePolicyClass { id });
        let err = agg.handle_command(&None, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::PolicyClassNotFound(eid) if eid == id),
            "expected PolicyClassNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_delete_ua_missing_id_returns_not_found() {
        let agg = make_aggregate();
        let mut graph = PolicyGraph::new();
        graph.add_pc(PolicyClass {
            id: Uuid::new_v4(),
            name: "test_pc".to_string(),
        });
        let state = Some(PolicyState { graph, version: 1 });
        let missing_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::DeleteUserAttribute { id: missing_id });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::UserAttributeNotFound(id) if id == missing_id),
            "expected UserAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_delete_oa_missing_id_returns_not_found() {
        let agg = make_aggregate();
        let mut graph = PolicyGraph::new();
        graph.add_pc(PolicyClass {
            id: Uuid::new_v4(),
            name: "test_pc".to_string(),
        });
        let state = Some(PolicyState { graph, version: 1 });
        let missing_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::DeleteObjectAttribute { id: missing_id });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::ObjectAttributeNotFound(id) if id == missing_id),
            "expected ObjectAttributeNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_delete_pc_missing_id_returns_not_found() {
        let agg = make_aggregate();
        let mut graph = PolicyGraph::new();
        graph.add_ua(UserAttribute {
            id: Uuid::new_v4(),
            name: "test_ua".to_string(),
            matcher: AttributeMatcher::All,
        });
        let state = Some(PolicyState { graph, version: 1 });
        let missing_id = Uuid::new_v4();
        let command = cmd(PolicyCommand::DeletePolicyClass { id: missing_id });
        let err = agg.handle_command(&state, command).await.unwrap_err();
        assert!(
            matches!(err, PolicyCommandError::PolicyClassNotFound(id) if id == missing_id),
            "expected PolicyClassNotFound, got: {err:?}"
        );
    }

    // =========================================================
    // handle_command — delete commands (round-trip via handle)
    // =========================================================

    #[tokio::test]
    async fn delete_ua_round_trip_cascades_associations() {
        let agg = make_aggregate();
        let actor = Some(PolicyActor { id: Uuid::new_v4() });
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();

        for cmd_payload in [
            PolicyCommand::CreateUserAttribute {
                id: ua_id,
                name: "admins".to_string(),
                matcher: AttributeMatcher::All,
            },
            PolicyCommand::CreateObjectAttribute {
                id: oa_id,
                name: "alpha_jobs".to_string(),
                resource_type: "job".to_string(),
                matcher: AttributeMatcher::All,
            },
        ] {
            agg.handle(Command::new(
                POLICY_AGGREGATE_ID,
                cmd_payload,
                actor.clone(),
                None,
            ))
            .await
            .unwrap();
        }
        agg.handle(Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreateAssociation {
                ua_id,
                target: AssociationTarget::ObjectAttribute(oa_id),
                operations: HashSet::from(["read".to_string()]),
            },
            actor.clone(),
            None,
        ))
        .await
        .unwrap();

        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::DeleteUserAttribute { id: ua_id },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();

        assert!(!state.graph.user_attributes.contains_key(&ua_id));
        assert!(state.graph.associations_for_ua(ua_id).is_empty());
    }

    #[tokio::test]
    async fn delete_ua_round_trip_removes_node_from_graph() {
        let agg = make_aggregate();
        let actor = Some(PolicyActor { id: Uuid::new_v4() });
        let ua_id = Uuid::new_v4();

        agg.handle(Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreateUserAttribute {
                id: ua_id,
                name: "admins".to_string(),
                matcher: AttributeMatcher::All,
            },
            actor.clone(),
            None,
        ))
        .await
        .unwrap();

        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::DeleteUserAttribute { id: ua_id },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();

        assert!(!state.graph.user_attributes.contains_key(&ua_id));
        assert!(
            state
                .graph
                .matching_uas(&std::collections::HashMap::new())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn delete_oa_round_trip_removes_node_from_graph() {
        let agg = make_aggregate();
        let actor = Some(PolicyActor { id: Uuid::new_v4() });
        let oa_id = Uuid::new_v4();

        agg.handle(Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreateObjectAttribute {
                id: oa_id,
                name: "alpha_jobs".to_string(),
                resource_type: "job".to_string(),
                matcher: AttributeMatcher::All,
            },
            actor.clone(),
            None,
        ))
        .await
        .unwrap();

        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::DeleteObjectAttribute { id: oa_id },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();

        assert!(!state.graph.object_attributes.contains_key(&oa_id));
        assert!(state.graph.get_oa(oa_id).is_none());
    }

    #[tokio::test]
    async fn delete_pc_round_trip_removes_node_from_graph() {
        let agg = make_aggregate();
        let actor = Some(PolicyActor { id: Uuid::new_v4() });
        let pc_id = Uuid::new_v4();

        agg.handle(Command::new(
            POLICY_AGGREGATE_ID,
            PolicyCommand::CreatePolicyClass {
                id: pc_id,
                name: "platform".to_string(),
            },
            actor.clone(),
            None,
        ))
        .await
        .unwrap();

        let state = agg
            .handle(Command::new(
                POLICY_AGGREGATE_ID,
                PolicyCommand::DeletePolicyClass { id: pc_id },
                actor.clone(),
                None,
            ))
            .await
            .unwrap()
            .unwrap();

        assert!(!state.graph.policy_classes.contains_key(&pc_id));
    }
}
