//! # Policy Aggregate
//!
//! Event-sourced persistence layer for the policy graph, using the
//! [epoch](https://github.com/Istar-Eldritch/epoch) CQRS/event-sourcing framework.
//!
//! This module defines:
//! - [`PolicyEvent`] — events emitted by policy mutations
//! - [`PolicyCommand`] — commands that mutate the policy graph
//! - [`PolicyState`] — the persisted aggregate state wrapping [`PolicyGraph`](crate::PolicyGraph)
//! - [`PolicyAggregate`] — the event-sourced aggregate handling commands and applying events
//! - [`PolicyActor`] — credentials carrying the actor ID for audit trails

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::{Uuid, uuid};

use epoch_core::prelude::*;
use epoch_derive::EventData;

use crate::{AssociationTarget, AttributeMatcher, PolicyGraph};

// Used in Phase 3/4 event application
#[allow(unused_imports)]
use crate::{Association, ObjectAttribute, PolicyClass, UserAttribute};

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
    /// Create a permission association from a UA to a target with operations.
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
}

/// Events emitted by the policy aggregate.
///
/// Events mirror commands 1:1 with past-tense naming. Each event carries
/// exactly the data needed to replay the corresponding [`PolicyGraph`](crate::PolicyGraph)
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
}

impl TryFrom<&PolicyEvent> for PolicyEvent {
    type Error = EnumConversionError;

    fn try_from(value: &PolicyEvent) -> Result<Self, Self::Error> {
        Ok(value.clone())
    }
}

/// The persisted state of the policy aggregate.
///
/// Wraps a [`PolicyGraph`](crate::PolicyGraph) with epoch version tracking.
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
/// This is an uninhabited enum — the [`EventApplicator::apply`] method
/// delegates to infallible [`PolicyGraph`](crate::PolicyGraph) mutation
/// methods and can never fail.
#[derive(Debug, thiserror::Error)]
pub enum PolicyApplyError {}

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

/// The event-sourced policy aggregate.
///
/// Generic over the event store (`ES`) and state store (`SS`) backends,
/// so the consuming application or tests supply the concrete implementations.
///
/// # Example (with in-memory backends for testing)
///
/// ```ignore
/// use epoch_mem::{InMemoryEventBus, InMemoryEventStore, InMemoryStateStore};
///
/// let bus = InMemoryEventBus::<PolicyEvent>::new();
/// let event_store = InMemoryEventStore::new(bus);
/// let state_store = InMemoryStateStore::<PolicyState>::new();
/// let aggregate = PolicyAggregate::new(event_store, state_store);
/// ```
#[allow(dead_code)]
pub struct PolicyAggregate<ES, SS> {
    pub(crate) event_store: ES,
    pub(crate) state_store: SS,
}

impl<ES, SS> PolicyAggregate<ES, SS> {
    /// Creates a new `PolicyAggregate` with the given event and state stores.
    pub fn new(event_store: ES, state_store: SS) -> Self {
        Self {
            event_store,
            state_store,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyView;

    use epoch_mem::{InMemoryEventBus, InMemoryEventStore, InMemoryStateStore};

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
        let _aggregate = PolicyAggregate::new(event_store, state_store);
    }
}
