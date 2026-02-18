# Spec: Graph Model, Node Types & PolicyView

- **Status**: Draft
- **Created**: 2026-02-18
- **Epic**: Feature 1 of `docs/2602181244_epic_sentinel_library.typ`
- **Crate**: `sentinel_core`

---

## PART I: Requirements

### Problem Statement

**Business context**: Sentinel is an NGAC-inspired authorization library. Before any PEP logic (`evaluate`, `scope`) or event-sourcing integration can be built, the foundational graph model must exist — the node types, the matching logic, the read-access trait, and the concrete in-memory graph. Every subsequent feature (aggregate, PEP evaluate, PEP scope, integration tests, derive macros) depends on this foundation.

**Current state**: `sentinel_core/src/lib.rs` contains only a module-level doc comment and `#![deny(missing_docs)]`. No types, traits, or logic exist yet. The crate already depends on `uuid`, `serde`, and `thiserror` — all needed for this feature. No `epoch_core` dependency is needed; this feature is pure data structures and trait definitions.

**Key issues**:
1. No authorization model types exist — downstream features are blocked.
2. The `PolicyView` trait must be defined before PEP functions can be written generically.
3. The `PolicyGraph` struct must support both read access (via `PolicyView`) and mutation (for the aggregate event applicator in Feature 2).

### Requirements

**R1 — AttributeMatcher enum**: Implement `AttributeMatcher` with two variants:
- `All` — wildcard, matches any input.
- `Matching { key: String, values: Vec<String> }` — matches when the input `HashMap` contains the `key` and its value is in `values`.

Both variants must implement a `matches(&self, attrs: &HashMap<String, String>) -> bool` method. `All` always returns `true`. `Matching` returns `true` if `attrs.get(key)` is `Some(v)` and `values.contains(v)`. If the key is absent or the value is not in the set, returns `false`.

**R2 — Node types**: Implement three node type structs with all fields `pub`:

- `UserAttribute { id: Uuid, name: String, matcher: AttributeMatcher }` — represents a role, group, or subject category. The matcher determines which subjects match this UA.
- `ObjectAttribute { id: Uuid, name: String, resource_type: String, matcher: AttributeMatcher }` — represents a resource scope. The `resource_type` identifies which kind of resource this OA applies to; the matcher determines which specific resources match.
- `PolicyClass { id: Uuid, name: String }` — a top-level policy scope grouping.

**R3 — AssociationTarget and Association**: Implement:
- `AssociationTarget` enum with variants `ObjectAttribute(Uuid)` and `PolicyClass(Uuid)`.
- `Association { ua_id: Uuid, target: AssociationTarget, operations: HashSet<String> }` — a permission grant linking a UA to a target with a set of allowed operations.

**R4 — PolicyView trait**: Define a `PolicyView` trait with four methods:

```rust
pub trait PolicyView {
    fn matching_uas(&self, subject_attrs: &HashMap<String, String>) -> Vec<&UserAttribute>;
    fn associations_for_ua(&self, ua_id: Uuid) -> Vec<&Association>;
    fn get_oa(&self, oa_id: Uuid) -> Option<&ObjectAttribute>;
    fn oas_for_pc(&self, pc_id: Uuid, resource_type: &str) -> Vec<&ObjectAttribute>;
}
```

- `matching_uas`: Returns all UAs whose `matcher.matches(subject_attrs)` is `true`.
- `associations_for_ua`: Returns all associations where `ua_id` matches.
- `get_oa`: Looks up an OA by ID.
- `oas_for_pc`: Returns all OAs assigned to the given PC that have the specified `resource_type`.

**R5 — PolicyGraph struct**: Implement `PolicyGraph` as the concrete in-memory graph with:
- Internal storage: `HashMap<Uuid, UserAttribute>`, `HashMap<Uuid, ObjectAttribute>`, `HashMap<Uuid, PolicyClass>`, `Vec<Association>`, `HashSet<(Uuid, Uuid)>` for OA→PC assignments.
- A `new()` constructor returning an empty graph.
- Seven mutation methods (1:1 with the Feature 2 command set):
  - `add_ua(&mut self, ua: UserAttribute)` — inserts a UA.
  - `add_oa(&mut self, oa: ObjectAttribute)` — inserts an OA.
  - `add_pc(&mut self, pc: PolicyClass)` — inserts a PC.
  - `add_association(&mut self, assoc: Association)` — appends an association.
  - `remove_association(&mut self, ua_id: Uuid, target: &AssociationTarget)` — removes matching association(s).
  - `assign_oa_to_pc(&mut self, oa_id: Uuid, pc_id: Uuid)` — adds an OA→PC assignment.
  - `unassign_oa_from_pc(&mut self, oa_id: Uuid, pc_id: Uuid)` — removes an OA→PC assignment.

**R6 — PolicyGraph implements PolicyView**: `PolicyGraph` must implement the `PolicyView` trait, providing the concrete query logic using its internal storage.

**R7 — Serde derives**: All node types (`UserAttribute`, `ObjectAttribute`, `PolicyClass`, `AttributeMatcher`, `Association`, `AssociationTarget`) must derive `Serialize` and `Deserialize` for epoch event serialization in Feature 2. `PolicyGraph` must also derive or implement `Serialize`/`Deserialize` for state store persistence.

**R8 — Debug and Clone**: All public types must derive `Debug` and `Clone`. `AssociationTarget` must also derive `PartialEq` and `Eq` (needed for `remove_association` comparison). `AttributeMatcher` must derive `PartialEq` for test assertions.

**R9 — No epoch dependency**: This feature must not introduce any dependency on `epoch_core`. The graph model is pure data structures and traits. The epoch integration is Feature 2.

**R10 — Rustdoc**: All public types, fields, methods, and the `PolicyView` trait must have rustdoc comments.

### Success Criteria

- [ ] `AttributeMatcher::All.matches(any_map)` returns `true`
- [ ] `AttributeMatcher::Matching` returns `true` only when key exists and value is in the set
- [ ] `AttributeMatcher::Matching` returns `false` when key is absent
- [ ] `AttributeMatcher::Matching` returns `false` when key exists but value is not in set
- [ ] `UserAttribute`, `ObjectAttribute`, `PolicyClass` structs are constructable with all fields public
- [ ] `Association` holds a `HashSet<String>` of operations
- [ ] `AssociationTarget` has `ObjectAttribute(Uuid)` and `PolicyClass(Uuid)` variants
- [ ] `PolicyGraph::new()` creates an empty graph
- [ ] `add_ua` / `add_oa` / `add_pc` insert nodes retrievable via `PolicyView` methods
- [ ] `add_association` makes association visible via `associations_for_ua`
- [ ] `remove_association` removes the matching association
- [ ] `assign_oa_to_pc` / `unassign_oa_from_pc` affect `oas_for_pc` results
- [ ] `matching_uas` returns only UAs whose matcher matches the given subject attributes
- [ ] `oas_for_pc` filters by both `pc_id` and `resource_type`
- [ ] `get_oa` returns `Some` for existing OAs and `None` for missing ones
- [ ] All public types derive `Serialize`, `Deserialize`, `Debug`, `Clone`
- [ ] `cargo test` passes, `cargo clippy -- -D warnings` clean, `cargo fmt` clean
- [ ] All public APIs have rustdoc comments
- [ ] No `epoch_core` dependency introduced

### Out of Scope

- **PEP functions** (`evaluate`, `scope`) — Feature 3 and Feature 4
- **Event sourcing** (`PolicyState`, aggregate commands/events) — Feature 2
- **Error types for command validation** (e.g., "UA not found") — Feature 2 handles command validation; `PolicyGraph` mutation methods are infallible (insert-or-overwrite semantics for nodes, no-op for duplicate assignments)
- **Node removal methods** (`remove_ua`, `remove_oa`, `remove_pc`) — no corresponding commands in the epic
- **UA→UA, OA→OA hierarchy** — explicitly deferred in the epic
- **Derive macros** (`ResourceAttributes`, `SubjectAttributes`) — Feature 6

### Open Questions

*None* — all ambiguities were resolved during discovery:
1. ~~`AttributeMatcher::Matching.values` type~~ → `Vec<String>` (matches epic)
2. ~~Mutation method set~~ → 7 methods mirroring Feature 2 commands 1:1
3. ~~OA→PC assignment storage~~ → `HashSet<(Uuid, Uuid)>`

---

## PART II: High-Level Implementation Plan

All work is in `sentinel_core/src/`. Following the project's code organization convention, this starts as a single file (`lib.rs`) since the total code (types + trait + struct + impl + tests) will be well under the 500–1000 line split threshold.

| Phase | Focus | Effort |
|-------|-------|--------|
| Phase 1 | Core types: `AttributeMatcher` enum with `matches()` method, unit tests for all matching scenarios | 0.5 days |
| Phase 2 | Node types and association types: `UserAttribute`, `ObjectAttribute`, `PolicyClass`, `AssociationTarget`, `Association` with serde/debug/clone derives | 0.5 days |
| Phase 3 | `PolicyView` trait definition and `PolicyGraph` struct with internal storage and `new()` constructor | 0.5 days |
| Phase 4 | `PolicyGraph` mutation methods (7 methods) with unit tests for each | 0.5 days |
| Phase 5 | `PolicyView` implementation for `PolicyGraph` with comprehensive query tests | 0.5 days |
| Phase 6 | Rustdoc, clippy/fmt cleanup, final verification | 0.25 days |

**Total estimate**: ~2.5 days

### Architectural Guidance

- **Single file**: All types, the trait, the struct, and tests go in `sentinel_core/src/lib.rs` for now. The file will be well under the complexity threshold. If it grows during later features, it can be split then.
- **TDD**: Each phase writes failing tests first, then implements to make them pass.
- **No new dependencies**: `uuid`, `serde`, and `thiserror` are already in `Cargo.toml`. `std::collections::HashMap` and `HashSet` are from the standard library. No additions needed.
- **Infallible mutations**: `PolicyGraph` mutation methods do not return `Result`. `add_ua`/`add_oa`/`add_pc` insert-or-overwrite (HashMap semantics). `add_association` appends. `remove_association` is a no-op if not found. `assign_oa_to_pc`/`unassign_oa_from_pc` use `HashSet` insert/remove semantics. This keeps the graph layer simple — validation belongs in the aggregate command handler (Feature 2).
- **Derive strategy**: Use `#[derive(Debug, Clone, Serialize, Deserialize)]` on all types. Add `PartialEq, Eq` on `AssociationTarget` and `AttributeMatcher` since they're needed for comparisons and test assertions.
