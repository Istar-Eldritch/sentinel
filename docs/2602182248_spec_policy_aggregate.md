# Spec 2602182248 — Policy Aggregate

**Status**: Draft
**Created**: 2026-02-18
**Feature**: Feature 2 — Policy Aggregate (from `docs/2602181244_epic_sentinel_library.typ`)

---

## Part I: Requirements

### 1. Problem Statement

The policy graph (`PolicyGraph`) implemented in Feature 1 is a pure in-memory data structure with no persistence. Without persistence, the policy graph is lost on every restart and there is no audit trail of who made which policy changes.

This feature adds an event-sourced persistence layer using the [epoch](https://github.com/Istar-Eldritch/epoch) framework. Policy mutations (creating nodes, adding associations, assigning OAs to PCs) become commands processed by a `PolicyAggregate`. Each command produces an event that is stored immutably in an event store. The aggregate state (`PolicyState`, wrapping the `PolicyGraph`) is rebuilt from these events and persisted for fast reads.

The result: the policy graph survives restarts, every change is auditable with an actor ID, and PEP evaluation (`evaluate`/`scope`, Feature 3/4) can read `state.graph` directly without any epoch infrastructure.

### 2. Requirements

**R1 — Epoch dependency**: `sentinel_core` depends on `epoch_core` and `epoch_derive` (production) and `epoch_mem` (dev/test only). All three reference the git repository `https://github.com/Istar-Eldritch/epoch.git`. No `sentinel_*` crate gains a dependency on `epoch_pg` or any other storage backend — those are supplied by the consuming application.

**R2 — PolicyEvent enum**: A `PolicyEvent` enum is defined with seven variants, one per mutation command, using past-tense naming. `PolicyEvent` derives `EventData` (from `epoch_derive`), `Debug`, `Clone`, `Serialize`, and `Deserialize`. It serves as both the superset event type (`ED` in `Aggregate<ED>`) and the subset `EventType` (no `#[subset_enum]` needed — single aggregate).

**R3 — PolicyCommand enum**: A `PolicyCommand` enum is defined with seven variants mirroring `PolicyEvent`. It implements `TryFrom<PolicyCommand>` trivially (identity clone — always succeeds), satisfying the `Aggregate` trait's `Command: TryFrom<CommandData>` bound for a single-aggregate system.

**R4 — PolicyActor credentials**: A `PolicyActor { pub id: Uuid }` struct is defined as the `CommandCredentials` type. Every command must carry a `PolicyActor` so the actor ID is stamped on every produced event via the epoch `Event::actor_id` field. This provides a full audit trail of policy changes.

**R5 — PolicyState**: A `PolicyState` struct wraps a `PolicyGraph` and implements epoch's `EventApplicatorState` and `AggregateState` traits. It exposes `pub graph: PolicyGraph` for direct read access by PEP functions. The version field is private, managed exclusively by epoch's machinery.

**R6 — Fixed aggregate ID**: A `pub const POLICY_AGGREGATE_ID: Uuid` is defined in the aggregate module using the `uuid!` macro. All commands target this fixed ID. There is exactly one policy aggregate per application instance.

**R7 — PolicyAggregate**: A `PolicyAggregate<ES, SS>` struct is generic over the event store (`ES`) and state store (`SS`) backends. This keeps `sentinel_core` free of `epoch_mem` as a production dependency — the concrete store types are provided by the consuming application (or tests).

**R8 — EventApplicator implementation**: `PolicyAggregate` implements `EventApplicator<PolicyEvent>`. The `apply` method delegates to `PolicyGraph` mutation methods (`add_ua`, `add_oa`, etc.). The apply error type `PolicyApplyError` is an uninhabited enum (no variants) — `apply` is infallible.

**R9 — Aggregate implementation**: `PolicyAggregate` implements `Aggregate<PolicyEvent>`. The `handle_command` method validates existence of referenced nodes against the current state before emitting an event. It stamps the actor ID from `command.credentials` onto every produced event.

**R10 — Node existence validation**: Commands that reference existing nodes (`CreateAssociation`, `RemoveAssociation`, `AssignOaToPc`, `UnassignOaFromPc`) return a typed error when a referenced node does not exist. When state is `None` (aggregate uninitialised), all reference commands return the appropriate `NotFound` error. Creation commands (`CreateUserAttribute`, `CreateObjectAttribute`, `CreatePolicyClass`) work against `None` state normally, initialising the graph.

**R11 — Documentation**: All public types and functions in the new `aggregate` module have rustdoc comments. `sentinel_core/src/lib.rs` re-exports the aggregate module as `pub mod aggregate`.

**R12 — Tests**: Unit and integration tests cover all commands (happy path and error paths), aggregate round-trips using `epoch_mem` in-memory backends, and event/state persistence. Tests use `#[tokio::test]` and `epoch_mem` stores.

### 3. Success Criteria

- [ ] `cargo build` succeeds with new epoch dependencies added to `sentinel_core/Cargo.toml`
- [ ] `PolicyEvent` derives `EventData` and serializes/deserializes correctly (serde roundtrip)
- [ ] `PolicyCommand` implements `TryFrom<PolicyCommand>` (trivial identity)
- [ ] `PolicyState` implements `EventApplicatorState` and `AggregateState`; `get_id()` returns `&POLICY_AGGREGATE_ID`
- [ ] `PolicyAggregate::new(event_store, state_store)` compiles with in-memory backends
- [ ] All 7 creation/mutation commands produce the correct event and update state
- [ ] `CreateAssociation` with non-existent `ua_id` returns `PolicyCommandError::UserAttributeNotFound`
- [ ] `CreateAssociation` with non-existent OA target returns `PolicyCommandError::ObjectAttributeNotFound`
- [ ] `CreateAssociation` with non-existent PC target returns `PolicyCommandError::PolicyClassNotFound`
- [ ] `AssignOaToPc` with non-existent `oa_id` returns `PolicyCommandError::ObjectAttributeNotFound`
- [ ] `AssignOaToPc` with non-existent `pc_id` returns `PolicyCommandError::PolicyClassNotFound`
- [ ] Reference commands against `None` state return `NotFound` errors
- [ ] Produced events have `actor_id` set to `command.credentials.map(|a| a.id)`
- [ ] Aggregate round-trip: issue commands → events stored → state rebuilt → `state.graph` queryable
- [ ] `PolicyGraph` in `lib.rs` has zero epoch imports — remains epoch-free
- [ ] `cargo test` passes, `cargo clippy -- -D warnings` zero warnings, `cargo fmt` clean
- [ ] All public APIs in `aggregate.rs` have rustdoc comments

### 4. Out of Scope

- PEP `evaluate()` and `scope()` functions (Features 3 & 4)
- Integration tests with the full PEP stack (Feature 5)
- PostgreSQL or any non-memory backend configuration
- `TransactionalAggregate` implementation (not needed for MVP)
- UA→UA, OA→OA, PC→PC hierarchy
- Hierarchical administration (governing who can modify the policy graph)
- `sentinel_derive` changes
- `sentinel` facade crate changes (re-exports are already wired)

### 5. Open Questions

None — all design decisions resolved during discovery.

---

## Part II: Technical Design

### 1. Dependency Changes

**`sentinel_core/Cargo.toml`** — add to `[dependencies]`:

```toml
async-trait = "0.1"
thiserror = "1.0"
tokio = { version = "1", features = ["full"] }
epoch_core = { git = "https://github.com/Istar-Eldritch/epoch.git", version = "0.1.0" }
epoch_derive = { git = "https://github.com/Istar-Eldritch/epoch.git", version = "0.1.0" }
```

Add to `[dev-dependencies]`:

```toml
tokio = { version = "1", features = ["full"] }
epoch_mem = { git = "https://github.com/Istar-Eldritch/epoch.git", version = "0.1.0" }
```

Also add the `uuid` crate feature `"macros"` (needed for `uuid!` macro):

```toml
uuid = { version = "1.17.0", features = ["serde", "v4", "macros"] }
```

**`sentinel_core/src/lib.rs`** — add at the bottom:

```rust
pub mod aggregate;
```

### 2. Module Structure

All new code lives in a single file: `sentinel_core/src/aggregate.rs`.

The `PolicyGraph` in `lib.rs` remains completely unchanged — no epoch imports there.

```
sentinel_core/src/
├── lib.rs           # existing — add `pub mod aggregate;` at bottom
└── aggregate.rs     # NEW — all epoch-dependent types
```

If `aggregate.rs` grows beyond ~500 lines or has clear conceptual divisions, it may be split into a directory (`aggregate/mod.rs`, etc.) — but start as a single file.

### 3. Type Definitions

#### `POLICY_AGGREGATE_ID`

```rust
use uuid::{uuid, Uuid};

/// The well-known fixed UUID for the single policy aggregate.
///
/// All policy commands must target this ID. There is exactly one
/// policy aggregate per application instance.
pub const POLICY_AGGREGATE_ID: Uuid = uuid!("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
```

(Any valid UUID literal is acceptable — choose one and hardcode it permanently.)

#### `PolicyActor`

```rust
/// Credentials for policy commands, carrying the actor ID for audit purposes.
///
/// Every policy mutation is stamped with the actor ID on the produced event,
/// providing a full audit trail of who made each policy change.
#[derive(Debug, Clone)]
pub struct PolicyActor {
    /// The unique identifier of the actor performing the policy mutation.
    pub id: Uuid,
}
```

#### `PolicyCommand`

```rust
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
```

`TryFrom<PolicyCommand>` implementation (trivial identity — single aggregate, always succeeds):

```rust
impl TryFrom<PolicyCommand> for PolicyCommand {
    type Error = std::convert::Infallible;

    fn try_from(value: PolicyCommand) -> Result<Self, Self::Error> {
        Ok(value)
    }
}
```

#### `PolicyEvent`

```rust
/// Events emitted by the policy aggregate.
///
/// Events mirror commands 1:1 with past-tense naming. Each event carries
/// exactly the data needed to replay the corresponding [`PolicyGraph`] mutation.
///
/// `PolicyEvent` serves as both the superset event type and the subset
/// `EventType` — no `#[subset_enum]` is needed since sentinel has a single aggregate.
#[derive(Debug, Clone, Serialize, Deserialize, EventData)]
pub enum PolicyEvent {
    /// A user attribute node was created.
    UserAttributeCreated {
        id: Uuid,
        name: String,
        matcher: AttributeMatcher,
    },
    /// An object attribute node was created.
    ObjectAttributeCreated {
        id: Uuid,
        name: String,
        resource_type: String,
        matcher: AttributeMatcher,
    },
    /// A policy class node was created.
    PolicyClassCreated {
        id: Uuid,
        name: String,
    },
    /// A permission association was created.
    AssociationCreated {
        ua_id: Uuid,
        target: AssociationTarget,
        operations: HashSet<String>,
    },
    /// A permission association was removed.
    AssociationRemoved {
        ua_id: Uuid,
        target: AssociationTarget,
    },
    /// An OA was assigned to a PC.
    OaAssignedToPc {
        oa_id: Uuid,
        pc_id: Uuid,
    },
    /// An OA was unassigned from a PC.
    OaUnassignedFromPc {
        oa_id: Uuid,
        pc_id: Uuid,
    },
}
```

`TryFrom<&PolicyEvent>` implementation (required by `EventApplicator::EventType` bound):

```rust
impl TryFrom<&PolicyEvent> for PolicyEvent {
    type Error = EnumConversionError;

    fn try_from(value: &PolicyEvent) -> Result<Self, Self::Error> {
        Ok(value.clone())
    }
}
```

#### `PolicyState`

```rust
/// The persisted state of the policy aggregate.
///
/// Wraps a [`PolicyGraph`] with epoch version tracking. Access `state.graph`
/// directly for PEP evaluation:
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
```

`EventApplicatorState` implementation:

```rust
impl EventApplicatorState for PolicyState {
    fn get_id(&self) -> &Uuid {
        &POLICY_AGGREGATE_ID
    }
}
```

`AggregateState` implementation:

```rust
impl AggregateState for PolicyState {
    fn get_version(&self) -> u64 {
        self.version
    }

    fn set_version(&mut self, version: u64) {
        self.version = version;
    }
}
```

#### `PolicyApplyError`

```rust
/// Error type for [`PolicyAggregate`]'s `EventApplicator::apply`.
///
/// This is an uninhabited enum — `apply` delegates to infallible
/// [`PolicyGraph`] mutation methods and can never fail.
#[derive(Debug, thiserror::Error)]
pub enum PolicyApplyError {}
```

#### `PolicyCommandError`

```rust
/// Error type for [`PolicyAggregate`]'s `Aggregate::handle_command`.
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
```

#### `PolicyAggregate`

```rust
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
pub struct PolicyAggregate<ES, SS> {
    event_store: ES,
    state_store: SS,
}

impl<ES, SS> PolicyAggregate<ES, SS> {
    /// Creates a new `PolicyAggregate` with the given stores.
    pub fn new(event_store: ES, state_store: SS) -> Self {
        Self { event_store, state_store }
    }
}
```

### 4. Trait Implementations

#### `EventApplicator<PolicyEvent>` for `PolicyAggregate<ES, SS>`

```
type State       = PolicyState
type StateStore  = SS
type EventType   = PolicyEvent   (same as ED — no subset needed)
type ApplyError  = PolicyApplyError
```

`apply` pattern:

```rust
fn apply(&self, state: Option<PolicyState>, event: &Event<PolicyEvent>)
    -> Result<Option<PolicyState>, PolicyApplyError>
{
    let mut state = state.unwrap_or_else(|| PolicyState {
        graph: PolicyGraph::new(),
        version: 0,
    });
    match event.data.as_ref().unwrap() {
        PolicyEvent::UserAttributeCreated { id, name, matcher } =>
            state.graph.add_ua(UserAttribute { id: *id, name: name.clone(), matcher: matcher.clone() }),
        PolicyEvent::ObjectAttributeCreated { id, name, resource_type, matcher } =>
            state.graph.add_oa(ObjectAttribute { id: *id, name: name.clone(), resource_type: resource_type.clone(), matcher: matcher.clone() }),
        PolicyEvent::PolicyClassCreated { id, name } =>
            state.graph.add_pc(PolicyClass { id: *id, name: name.clone() }),
        PolicyEvent::AssociationCreated { ua_id, target, operations } =>
            state.graph.add_association(Association { ua_id: *ua_id, target: target.clone(), operations: operations.clone() }),
        PolicyEvent::AssociationRemoved { ua_id, target } =>
            state.graph.remove_association(*ua_id, target),
        PolicyEvent::OaAssignedToPc { oa_id, pc_id } =>
            state.graph.assign_oa_to_pc(*oa_id, *pc_id),
        PolicyEvent::OaUnassignedFromPc { oa_id, pc_id } =>
            state.graph.unassign_oa_from_pc(*oa_id, *pc_id),
    }
    Ok(Some(state))
}
```

Key: `apply` always returns `Ok(Some(state))` — policy nodes are never deleted via events in this iteration, so state is never `None` after the first event.

`get_state_store` returns `self.state_store.clone()` — requires `SS: Clone`.

#### `Aggregate<PolicyEvent>` for `PolicyAggregate<ES, SS>`

```
type CommandData        = PolicyCommand
type CommandCredentials = PolicyActor
type Command            = PolicyCommand   (same — trivial TryFrom)
type AggregateError     = PolicyCommandError
type EventStore         = ES
```

`get_event_store` returns `self.event_store.clone()` — requires `ES: Clone`.

`handle_command` builds one event per command arm, stamping `actor_id`:

```rust
async fn handle_command(
    &self,
    state: &Option<PolicyState>,
    command: Command<PolicyCommand, PolicyActor>,
) -> Result<Vec<Event<PolicyEvent>>, PolicyCommandError>
```

Actor extraction helper (used in every arm):

```rust
let actor_id = command.credentials.as_ref().map(|a| a.id);
```

Event building pattern for each arm:

```rust
PolicyEvent::SomeVariant { .. }
    .into_builder()
    .stream_id(POLICY_AGGREGATE_ID)
    .actor_id(actor_id)
    .build()?
```

### 5. Validation Logic per Command

| Command | State `None` | State `Some` — checks |
|---|---|---|
| `CreateUserAttribute` | ✅ Proceed (emit event, `apply` initialises graph) | ✅ Proceed (no existence checks needed) |
| `CreateObjectAttribute` | ✅ Proceed | ✅ Proceed |
| `CreatePolicyClass` | ✅ Proceed | ✅ Proceed |
| `CreateAssociation` | ❌ `UserAttributeNotFound(ua_id)` | Check `ua_id` in `state.graph.user_attributes` → `UserAttributeNotFound`; check target: OA → `ObjectAttributeNotFound`, PC → `PolicyClassNotFound` |
| `RemoveAssociation` | ❌ `UserAttributeNotFound(ua_id)` | Check `ua_id` in `state.graph.user_attributes` → `UserAttributeNotFound`; check target exists → appropriate `NotFound` |
| `AssignOaToPc` | ❌ `ObjectAttributeNotFound(oa_id)` | Check `oa_id` → `ObjectAttributeNotFound`; check `pc_id` → `PolicyClassNotFound` |
| `UnassignOaFromPc` | ❌ `ObjectAttributeNotFound(oa_id)` | Check `oa_id` → `ObjectAttributeNotFound`; check `pc_id` → `PolicyClassNotFound` |

For `CreateAssociation` and `RemoveAssociation`, checking the `ua_id` first preserves a consistent error precedence (UA checked before target).

Note: `state.graph.user_attributes`, `state.graph.object_attributes`, and `state.graph.policy_classes` are `pub(crate)` fields on `PolicyGraph`. Since `aggregate.rs` is in the same crate as `lib.rs`, it can access them directly. Alternatively, add accessor methods to `PolicyGraph` — either approach is acceptable; prefer direct field access to avoid adding public API surface just for this purpose.

### 6. Required Imports in `aggregate.rs`

```rust
use std::collections::HashSet;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::{uuid, Uuid};
use epoch_core::prelude::*;
use epoch_derive::EventData;
use crate::{
    Association, AssociationTarget, AttributeMatcher, ObjectAttribute,
    PolicyClass, PolicyGraph, UserAttribute,
};
```

### 7. Trait Bounds on `PolicyAggregate<ES, SS>`

The `impl EventApplicator` and `impl Aggregate` blocks require these bounds:

```rust
impl<ES, SS> EventApplicator<PolicyEvent> for PolicyAggregate<ES, SS>
where
    ES: EventStoreBackend<EventType = PolicyEvent> + Send + Sync + Clone + 'static,
    SS: StateStoreBackend<PolicyState> + Send + Sync + Clone,
{ ... }

#[async_trait]
impl<ES, SS> Aggregate<PolicyEvent> for PolicyAggregate<ES, SS>
where
    ES: EventStoreBackend<EventType = PolicyEvent> + Send + Sync + Clone + 'static,
    SS: StateStoreBackend<PolicyState> + Send + Sync + Clone,
{ ... }
```

### 8. Test Plan

All tests live in a `#[cfg(test)]` module at the bottom of `aggregate.rs`. Tests use `epoch_mem` backends:

```rust
// Test helper — builds a fresh in-memory aggregate
fn make_aggregate() -> PolicyAggregate<
    InMemoryEventStore<InMemoryEventBus<PolicyEvent>>,
    InMemoryStateStore<PolicyState>,
> {
    let bus = InMemoryEventBus::new();
    let event_store = InMemoryEventStore::new(bus);
    let state_store = InMemoryStateStore::new();
    PolicyAggregate::new(event_store, state_store)
}

// Test helper — builds a Command with a test actor
fn cmd(data: PolicyCommand) -> Command<PolicyCommand, PolicyActor> {
    Command::new(
        POLICY_AGGREGATE_ID,
        data,
        Some(PolicyActor { id: Uuid::new_v4() }),
        None,
    )
}
```

#### Creation command tests

| Test | Description |
|---|---|
| `create_ua_produces_user_attribute_created_event` | `CreateUserAttribute` → `UserAttributeCreated` event, state has UA |
| `create_oa_produces_object_attribute_created_event` | `CreateObjectAttribute` → `ObjectAttributeCreated` event |
| `create_pc_produces_policy_class_created_event` | `CreatePolicyClass` → `PolicyClassCreated` event |
| `create_ua_works_against_none_state` | First command on fresh aggregate succeeds |
| `create_multiple_nodes_accumulate_in_graph` | UA + OA + PC commands each add to graph |

#### Association command tests

| Test | Description |
|---|---|
| `create_association_with_oa_target_succeeds` | UA + OA exist → `AssociationCreated` stored, graph has association |
| `create_association_with_pc_target_succeeds` | UA + PC exist → `AssociationCreated` stored |
| `create_association_missing_ua_returns_error` | `ua_id` not in graph → `UserAttributeNotFound` |
| `create_association_missing_oa_target_returns_error` | OA target not in graph → `ObjectAttributeNotFound` |
| `create_association_missing_pc_target_returns_error` | PC target not in graph → `PolicyClassNotFound` |
| `create_association_against_none_state_returns_error` | No commands yet → `UserAttributeNotFound` |
| `remove_association_succeeds` | Existing association is removed from graph |
| `remove_association_missing_ua_returns_error` | `ua_id` not in graph → `UserAttributeNotFound` |

#### OA→PC assignment tests

| Test | Description |
|---|---|
| `assign_oa_to_pc_succeeds` | OA + PC exist → `OaAssignedToPc` stored, assignment visible in graph |
| `assign_oa_to_pc_missing_oa_returns_error` | OA not in graph → `ObjectAttributeNotFound` |
| `assign_oa_to_pc_missing_pc_returns_error` | PC not in graph → `PolicyClassNotFound` |
| `unassign_oa_from_pc_succeeds` | Existing assignment removed |
| `unassign_oa_from_pc_missing_oa_returns_error` | OA not in graph → `ObjectAttributeNotFound` |
| `unassign_oa_from_pc_against_none_state_returns_error` | No state → `ObjectAttributeNotFound` |

#### Actor ID audit tests

| Test | Description |
|---|---|
| `events_carry_actor_id` | Produced event has `actor_id == Some(PolicyActor.id)` — requires reading from event store after command |

#### Round-trip tests

| Test | Description |
|---|---|
| `aggregate_round_trip_graph_queryable` | Issue UA + OA + PC + association commands; verify `state.graph` has correct nodes and `matching_uas` / `associations_for_ua` work |
| `policy_state_version_increments_per_command` | Each command increments `state.version` by 1 |

---

## Part III: Implementation Plan

| Phase | Focus | Effort |
|-------|-------|--------|
| Phase 1 | Dependency wiring — add epoch git deps to `sentinel_core/Cargo.toml`, add `pub mod aggregate` to `lib.rs`, create empty `aggregate.rs`, verify `cargo build` | 0.5h |
| Phase 2 | Core types — `POLICY_AGGREGATE_ID`, `PolicyActor`, `PolicyCommand` (with `TryFrom`), `PolicyEvent` (with `#[derive(EventData)]` and `TryFrom<&PolicyEvent>`), `PolicyState` (with both epoch traits), error enums | 1h |
| Phase 3 | `EventApplicator` implementation — `apply` method delegating to `PolicyGraph` mutations, `get_state_store` | 0.5h |
| Phase 4 | `Aggregate` implementation — `handle_command` with all 7 arms, node existence validation, actor ID stamping | 1h |
| Phase 5 | Tests — write failing tests first (TDD), then verify implementation passes all tests | 1.5h |
| Phase 6 | Polish — `cargo fmt`, `cargo clippy -- -D warnings`, rustdoc on all public items | 0.5h |
