# Spec 2602182248 — Policy Aggregate

- **Status**: ✅ Implemented
- **Created**: 2026-02-18
- **Completed**: 2026-02-19
- **Feature**: Feature 2 — Policy Aggregate (from `docs/2602181244_epic_sentinel_library.typ`)

---

## Problem Statement

The `PolicyGraph` from Feature 1 is a pure in-memory structure with no persistence or audit trail. This feature adds an event-sourced persistence layer using the [epoch](https://github.com/Istar-Eldritch/epoch) framework, so the policy graph survives restarts and every policy mutation is auditable with an actor ID.

---

## Solution Overview

Policy mutations become commands processed by `PolicyAggregate`. Each command is validated against the current state, produces an event stored immutably in an event store, and is replayed via `apply` to rebuild `PolicyState` (which wraps `PolicyGraph`). PEP functions (Features 3/4) read `state.graph` directly — no epoch infrastructure required at query time.

All epoch-dependent code lives in `sentinel_core/src/aggregate.rs`. The `PolicyGraph` in `lib.rs` remains epoch-free. Backend implementations (`epoch_mem`, `epoch_pg`) are supplied by the consuming application; `sentinel_core` depends only on `epoch_core` and `epoch_derive` in production.

---

## Key Design Decisions

### Fixed Single-Aggregate Architecture

A single `pub const POLICY_AGGREGATE_ID: Uuid` identifies the one policy aggregate per application instance. This keeps the model simple — there is one policy graph per application, not per tenant or per resource type.

### `PolicyCommand = PolicyEvent` as `CommandData`

A trivial `TryFrom<PolicyCommand> for PolicyCommand` (identity clone, always succeeds) satisfies epoch's `Command: TryFrom<CommandData>` bound. No separate command/event type mapping is needed for a single-aggregate system.

### Commands Mirror Events 1:1

Seven command variants map 1:1 to seven past-tense event variants. This direct correspondence keeps the aggregate handler straightforward — one command arm, one event emitted.

| Command | Event |
|---|---|
| `CreateUserAttribute` | `UserAttributeCreated` |
| `CreateObjectAttribute` | `ObjectAttributeCreated` |
| `CreatePolicyClass` | `PolicyClassCreated` |
| `CreateAssociation` | `AssociationCreated` |
| `RemoveAssociation` | `AssociationRemoved` |
| `AssignOaToPc` | `OaAssignedToPc` |
| `UnassignOaFromPc` | `OaUnassignedFromPc` |

### Infallible `apply`

`PolicyApplyError` is an uninhabited enum — `apply` delegates to the infallible `PolicyGraph` mutation methods and can never fail. This is consistent with the Feature 1 decision that validation belongs at the command handler level, not in graph mutations.

### `PolicyActor` as `CommandCredentials`

Every command carries a `PolicyActor { pub id: Uuid }` which is stamped onto the produced event's `actor_id` field, providing a full immutable audit trail of who made each policy change.

### Node Existence Validation at Command Time

Commands that reference existing nodes (`CreateAssociation`, `RemoveAssociation`, `AssignOaToPc`, `UnassignOaFromPc`) return typed errors when referenced nodes are absent. When state is `None` (uninitialized aggregate), all reference commands return the appropriate `NotFound` error. Creation commands work against `None` state, initializing the graph on first apply.

---

## Core API

### Types

```rust
pub const POLICY_AGGREGATE_ID: Uuid;  // fixed well-known UUID

pub struct PolicyActor { pub id: Uuid }

pub enum PolicyCommand { CreateUserAttribute { .. }, CreateObjectAttribute { .. },
    CreatePolicyClass { .. }, CreateAssociation { .. }, RemoveAssociation { .. },
    AssignOaToPc { .. }, UnassignOaFromPc { .. } }

#[derive(EventData)]
pub enum PolicyEvent { UserAttributeCreated { .. }, ObjectAttributeCreated { .. },
    PolicyClassCreated { .. }, AssociationCreated { .. }, AssociationRemoved { .. },
    OaAssignedToPc { .. }, OaUnassignedFromPc { .. } }

pub struct PolicyState { pub graph: PolicyGraph, version: u64 }  // implements EventApplicatorState + AggregateState

pub enum PolicyApplyError {}          // uninhabited — apply is infallible
pub enum PolicyCommandError { EventBuild(..), UserAttributeNotFound(Uuid),
    ObjectAttributeNotFound(Uuid), PolicyClassNotFound(Uuid) }

pub struct PolicyAggregate<ES, SS> { .. }  // generic over store backends
impl<ES, SS> PolicyAggregate<ES, SS> {
    pub fn new(event_store: ES, state_store: SS) -> Self;
}
```

### Validation Matrix

| Command | `None` state | `Some` state |
|---|---|---|
| `Create{UA,OA,PC}` | ✅ Proceed | ✅ Proceed |
| `CreateAssociation` | ❌ `UserAttributeNotFound` | Check `ua_id`, then target (OA or PC) |
| `RemoveAssociation` | ❌ `UserAttributeNotFound` | Check `ua_id`, then target |
| `AssignOaToPc` | ❌ `ObjectAttributeNotFound` | Check `oa_id`, then `pc_id` |
| `UnassignOaFromPc` | ❌ `ObjectAttributeNotFound` | Check `oa_id`, then `pc_id` |

---

## Out of Scope

- PEP `evaluate()` and `scope()` — Features 3 & 4
- PostgreSQL or non-memory backend configuration
- `TransactionalAggregate` implementation
- UA→UA, OA→OA, PC→PC hierarchy
- Node removal commands (`remove_ua`, `remove_oa`, `remove_pc`)
- Hierarchical administration (who can modify the policy graph)
