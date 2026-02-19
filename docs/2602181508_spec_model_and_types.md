# Spec: Graph Model, Node Types & PolicyView

- **Status**: ✅ Implemented
- **Created**: 2026-02-18
- **Completed**: 2026-02-19
- **Epic**: Feature 1 of `docs/2602181244_epic_sentinel_library.typ`
- **Crate**: `sentinel_core`

---

## Problem Statement

Before any PEP logic or event-sourcing integration can be built, the foundational graph model must exist — node types, attribute-matching logic, the `PolicyView` read-access trait, and the concrete in-memory graph. Every subsequent feature depends on this foundation.

---

## Solution Overview

All types, the trait, and the implementation live in `sentinel_core/src/lib.rs` (single-file, below the complexity split threshold). No `epoch_core` dependency is introduced — this is pure data structures and traits.

---

## Key Design Decisions

### Attribute-Matching over Object-in-Graph

`UserAttribute` and `ObjectAttribute` nodes carry an `AttributeMatcher` rather than referencing specific resource or subject IDs. This keeps the graph small (hundreds of nodes) regardless of data volume. Specific-object access is expressed as `Matching { key: "id", values: [specific_id] }`.

### Infallible Mutation Methods

`PolicyGraph` mutation methods do not return `Result`. Insert-or-overwrite semantics for nodes, append for associations, and `HashSet` insert/remove for assignments. Validation (e.g., "UA not found") belongs in the aggregate command handler (Feature 2), not the graph layer.

### `AssociationTarget` Enum

Associations can target either an `ObjectAttribute` or a `PolicyClass` directly. This supports both fine-grained resource-scoped permissions and broad policy-class grants without separate association types.

### OA→PC Assignments Stored Separately

OA-to-PC assignments are stored as a `HashSet<(Uuid, Uuid)>` independent of OA storage. This makes `oas_for_pc` queries efficient and keeps the OA struct itself free of parent-relationship fields.

---

## Core API

### `AttributeMatcher`

```rust
pub enum AttributeMatcher {
    All,
    Matching { key: String, values: Vec<String> },
}

impl AttributeMatcher {
    pub fn matches(&self, attrs: &HashMap<String, String>) -> bool;
}
```

`All` matches any input. `Matching` returns `true` only when the key exists and its value is in `values`.

### Node Types

```rust
pub struct UserAttribute   { pub id: Uuid, pub name: String, pub matcher: AttributeMatcher }
pub struct ObjectAttribute { pub id: Uuid, pub name: String, pub resource_type: String, pub matcher: AttributeMatcher }
pub struct PolicyClass     { pub id: Uuid, pub name: String }
```

### Associations

```rust
pub enum AssociationTarget { ObjectAttribute(Uuid), PolicyClass(Uuid) }
pub struct Association { pub ua_id: Uuid, pub target: AssociationTarget, pub operations: HashSet<String> }
```

### `PolicyView` Trait

```rust
pub trait PolicyView {
    fn matching_uas(&self, subject_attrs: &HashMap<String, String>) -> Vec<&UserAttribute>;
    fn associations_for_ua(&self, ua_id: Uuid) -> Vec<&Association>;
    fn get_oa(&self, oa_id: Uuid) -> Option<&ObjectAttribute>;
    fn oas_for_pc(&self, pc_id: Uuid, resource_type: &str) -> Vec<&ObjectAttribute>;
}
```

### `PolicyGraph` Mutations

```rust
impl PolicyGraph {
    pub fn new() -> Self;
    pub fn add_ua(&mut self, ua: UserAttribute);
    pub fn add_oa(&mut self, oa: ObjectAttribute);
    pub fn add_pc(&mut self, pc: PolicyClass);
    pub fn add_association(&mut self, assoc: Association);
    pub fn remove_association(&mut self, ua_id: Uuid, target: &AssociationTarget);
    pub fn assign_oa_to_pc(&mut self, oa_id: Uuid, pc_id: Uuid);
    pub fn unassign_oa_from_pc(&mut self, oa_id: Uuid, pc_id: Uuid);
}
```

The seven mutation methods correspond 1:1 with the Feature 2 command set.

---

## Out of Scope

- **UA→UA, OA→OA hierarchy** — explicitly deferred
- **Node removal** (`remove_ua`, `remove_oa`, `remove_pc`) — no corresponding commands in the epic
- **PEP functions** (`evaluate`, `scope`) — Features 3 and 4
- **Event sourcing** (`PolicyState`, aggregate commands/events) — Feature 2
- **Derive macros** (`ResourceAttributes`, `SubjectAttributes`) — Feature 6
