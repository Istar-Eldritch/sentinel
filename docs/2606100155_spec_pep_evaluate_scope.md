# Spec 2606100155 — PEP Evaluate & Scope

- **Status**: ✅ Approved — 2026-06-10 (D18 amended to multi-valued request attributes during review)
- **Created**: 2026-06-10
- **Features**: Feature 3 (PEP Evaluate) & Feature 4 (PEP Scope) from `docs/2602181244_epic_sentinel_library.typ`, plus aggregate hardening and design amendments from the 2026-06-10 design review
- **Crate**: `sentinel_core`
- **Supersedes**: Epic requirement R3 (in part) and the epic's Feature 4 `scope()` algorithm

---

## Problem Statement

The graph model (Feature 1) and policy aggregate (Feature 2) are complete, but the library cannot yet make authorization decisions. `evaluate()` and `scope()` — the two PEP entry points — are unimplemented.

A design review (2026-06-10, `d1ffb7df_reviewer_0_output.md`) found two soundness bugs in the epic's algorithm specifications that must be corrected before implementation:

1. **`evaluate()`/`scope()` disagree on UA→PC associations.** The epic's `scope()` returns `Unrestricted` whenever the PC has *any* OA of the requested resource type, while `evaluate()` additionally requires an OA's *matcher* to match the resource. A list endpoint could therefore show resources that point-checks deny (review counterexample: `(org_admins, org_alpha_pc, {read})` with `alpha_jobs { org_id ∈ [alpha] }` under the PC — `scope()` says `Unrestricted`, `evaluate()` denies a beta-org job).
2. **`scope()` cannot represent an `AttributeMatcher::All` OA.** `ScopeConstraint::Attribute { key, values }` has nothing to emit for a wildcard matcher; the naive algorithm would return `AccessScope::None` (no access) for a path `evaluate()` allows — breaking the "public resources" pattern.

The review also found an association-identity incoherence in the aggregate (duplicate grants silently erased on replay of `Create`/`Create`/`Remove`) and one `unwrap()` in library code (`aggregate.rs:296`).

---

## Solution Overview

Implement `evaluate()` and `scope()` in `sentinel_core/src/lib.rs` as free functions generic over `&impl PolicyView`, per the epic — with amended algorithms that restore the soundness invariant:

> **Invariant**: for any subject, operation, and resource type, the set of resources admitted by `scope()`'s output is exactly the set of resources for which `evaluate()` returns `Allow`.

A preliminary hardening phase fixes the aggregate issues so the storage layer is coherent before the PEP reads from it.

No new dependencies. No changes to `sentinel_derive` or the facade (Features 6–7 remain future work).

---

## Key Design Decisions (approved; supersede the epic where they conflict)

### D16 — UA→PC associations mean "union of the PC's OA scopes" (Option B)

A UA→PC association behaves exactly as if the UA were associated with **every OA currently assigned to that PC**. It is shorthand, not god-mode:

- `evaluate()`: allow only if some OA under the PC (matching the resource type) has a matcher matching the resource attributes — *unchanged from the epic's evaluate()*.
- `scope()`: **amended** — instead of returning `Unrestricted` on existence of OAs, OR-combine the matchers of the OAs under the PC, exactly as for direct UA→OA associations.

Consequences:
- `Unrestricted` is *derived* from the graph (an `All`-matcher OA is reachable), never *declared* by targeting a PC.
- The platform-admin pattern requires an `All`-matcher OA per resource type assigned to the platform PC (e.g., `all_jobs { resource_type: "job", matcher: All }`).
- Fail-closed: a PC with no OA for a resource type grants nothing for that type.
- Org-scoped grants compose naturally: `(alpha_admins, org_alpha_pc, {read})` grants read on alpha's jobs/files only, and auto-extends as OAs are added to the PC.

This amends epic R3 ("A UA→PC association with the required operation produces `AccessScope::Unrestricted`") — that sentence no longer holds unconditionally.

### D17 — `All`-matcher OA short-circuits to `Unrestricted`

In `scope()`, if **any** reachable candidate OA (via UA→OA directly or via UA→PC expansion) for the requested resource type and operation has `matcher: AttributeMatcher::All`, return `AccessScope::Unrestricted` immediately. Rationale: `X OR true = true`. This is what makes both the platform-admin and public-resources patterns produce correct scopes.

### D18 — Request attributes are multi-valued sets (`HashMap<String, HashSet<String>>`) *(amended at review, 2026-06-10)*

Both request sides (subject and resource attributes) are **multi-valued**: each key maps to a `HashSet<String>` of values. This makes multi-org membership (`org_id ∈ {alpha, beta}`) and multi-tag resources expressible. Matching semantics become **non-empty intersection**: `Matching { key, values }` matches when the input set for `key` shares at least one value with the matcher's `values`. A key mapped to an **empty set** behaves exactly like an absent key (fail-closed: `any` over an empty set is `false`).

Consequences:
- `AttributeMatcher::matches` and `PolicyView::matching_uas` change signature from `&HashMap<String, String>` to `&HashMap<String, HashSet<String>>` (see REQ-HARD-004) — a breaking change to the implemented Feature 1 API, made now while no external consumers exist and before the derive macros (Feature 6) freeze `Into<HashMap<String, HashSet<String>>>` into generated code.
- The policy side (`Matching::values`) stays `Vec<String>`: it is part of persisted events (serialization stability) and its ordering keeps `scope()`'s constraint merging deterministic (REQ-SCOPE-005).
- Soundness is preserved: a constraint `Attribute { key, values }` admits a resource when the resource's value-set for `key` **intersects** `values` (single-valued columns translate to SQL `key IN (...)` as before; multi-valued resource attributes are the application's translation concern).

### D19 — Association identity is `(ua_id, target)`; create is an upsert

`PolicyGraph::add_association` replaces any existing association with the same `(ua_id, target)` instead of appending a duplicate. `CreateAssociation` thus means "set the operation set for this grant"; `RemoveAssociation` removes exactly one logical grant. This eliminates the replay hazard where `Create{read}` + `Create{write,delete}` + one `Remove` silently erased both grants.

### D20 — `apply()` rejects events with missing data (no `unwrap()` in library code)

`EventApplicator::apply` currently calls `event.data.as_ref().unwrap()`. `PolicyApplyError` gains an inhabited `MissingEventData` variant and the unwrap becomes an error return.

### Builder-style requests without `.build()`

Deviation from the epic's pseudo-code (within the spirit of epic R9): required fields (`operation`, `resource_type`) are constructor arguments and there is no `.build()` — the struct is its own builder via consuming chained setters. This makes an operation-less request unrepresentable rather than a runtime concern, while remaining additively extensible (future setters like `.environment_attrs(...)` are non-breaking).

---

## Requirements

Requirement IDs are stable and referenceable from the implementation plan, commits, and tests. Prefixes: `REQ-HARD-*` (aggregate/graph hardening), `REQ-EVAL-*` (Feature 3), `REQ-SCOPE-*` (Feature 4), `REQ-INV-*` (cross-cutting invariant), `REQ-DOC-*` (documentation-only).

### Phase 0 — Hardening

#### REQ-HARD-001 — Association upsert semantics (D19)

`PolicyGraph::add_association(&mut self, assoc: Association)` MUST replace any existing association with the same `(ua_id, target)` pair before inserting, so that at most one association exists per `(ua_id, target)` at all times. The method's rustdoc MUST describe the upsert contract. The rustdoc of `remove_association` MUST be updated to reflect that at most one entry can match (drop the "may be multiple matching entries" wording).

**Acceptance criteria:**
- Adding an association for an existing `(ua_id, target)` results in exactly one association for that pair, carrying the *new* operation set.
- Adding associations for distinct targets (or distinct UAs) still accumulates entries.
- The two existing tests that assert duplicate accumulation — `add_association_duplicate_creates_two_entries` and `add_association_same_target_different_ops_creates_two` (`lib.rs` ~lines 1021/1043) — are rewritten to assert **replacement**: after the second add, exactly one association exists for the pair, with the second operation set.

**Test obligations:** unit tests in `lib.rs` covering replace-on-same-pair, distinct-target accumulation, and operation-set replacement.

#### REQ-HARD-002 — Replay coherence for association grants (D19)

Replaying the event sequence `AssociationCreated(ua, target, {read})` → `AssociationCreated(ua, target, {write, delete})` → `AssociationRemoved(ua, target)` MUST yield a graph with **no** association for `(ua, target)`, and replaying only the first two events MUST yield exactly one association with operations `{write, delete}`. The `CreateAssociation` command rustdoc in `aggregate.rs` MUST document the "set the operation set for this grant" (upsert) semantics.

**Acceptance criteria:**
- The review's replay counterexample no longer silently erases an unintended grant: after the three-event replay the pair is absent; other associations on the same UA with different targets are unaffected.
- Live command handling and event replay produce identical graphs for the same sequence.

**Test obligations:** an aggregate-level test in `aggregate.rs` replaying the three-event scenario (via `apply`) and asserting the resulting graph state.

#### REQ-HARD-004 — Multi-valued attribute matching (D18)

`AttributeMatcher::matches` MUST take `&HashMap<String, HashSet<String>>` and return `true` for `Matching { key, values }` when the input contains `key` with at least one value present in `values` (non-empty intersection):

```rust
pub fn matches(&self, attrs: &HashMap<String, HashSet<String>>) -> bool {
    match self {
        AttributeMatcher::All => true,
        AttributeMatcher::Matching { key, values } => attrs
            .get(key)
            .is_some_and(|vs| vs.iter().any(|v| values.contains(v))),
    }
}
```

`PolicyView::matching_uas` (and `PolicyGraph`'s implementation) MUST take `subject_attrs: &HashMap<String, HashSet<String>>`. `AttributeMatcher::All` semantics are unchanged. This requirement is **foundational** — it lands before REQ-EVAL-*/REQ-SCOPE-* since the request types build on it.

**Acceptance criteria:**
- A subject with `org_id ∈ {alpha, beta}` matches a UA with `Matching { key: "org_id", values: ["alpha"] }`.
- A subject with `org_id ∈ {gamma}` does not match the same UA.
- A key mapped to an empty set never matches a `Matching` matcher on that key (fail-closed, equivalent to an absent key).
- `All` still matches the empty map and any map.
- Existing `AttributeMatcher`/`matching_uas` tests are migrated to the new signature with semantics-equivalent single-element sets.

**Test obligations:** unit tests in `lib.rs` for intersection match, disjoint no-match, empty-set no-match, and `All` unchanged.

#### REQ-HARD-003 — `apply()` returns an error for missing event data (D20)

`PolicyApplyError` MUST gain an inhabited variant:

```rust
/// Error type for [`PolicyAggregate`]'s event application.
#[derive(Debug, thiserror::Error)]
pub enum PolicyApplyError {
    /// The event envelope carried no event data.
    #[error("event {0} has no event data")]
    MissingEventData(Uuid),
}
```

The variant payload is the event envelope's `event.id` (epoch's `Event<D>` exposes `pub id: Uuid`). The `event.data.as_ref().unwrap()` at `aggregate.rs:296` MUST be replaced with `ok_or(...)?` returning this variant. The enum's rustdoc MUST drop the "uninhabited / infallible" wording.

> **Note (purge semantics)**: epoch sets `Event.data = None` not only on corruption but also **by design when an event is purged** (compliance deletion — see `epoch_core::Event::data` docs). Returning `MissingEventData` therefore means a purged policy event makes replay fail closed rather than silently skipping a graph mutation. This is the intended behavior for an authorization graph: purging policy events is not supported, and the variant's rustdoc MUST say so.

**Acceptance criteria:**
- `cargo build` succeeds with no `unwrap()`/`expect()` remaining in non-test code of `aggregate.rs` or `lib.rs`.
- Calling `apply` with an `Event` whose `data` is `None` returns `Err(PolicyApplyError::MissingEventData(..))` and does not panic.

**Test obligations:** a unit test in `aggregate.rs` constructing an event with `data: None` and asserting the error variant.

### Feature 3 — PEP Evaluate

#### REQ-EVAL-001 — `Decision` type

`sentinel_core/src/lib.rs` MUST define:

```rust
/// The outcome of a point authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The subject may perform the operation on the resource.
    Allow,
    /// The subject may not perform the operation on the resource.
    Deny,
}
```

**Acceptance criteria:** public, rustdoc'd, derives exactly as above (no `Serialize`/`Deserialize` — decisions are not persisted).

#### REQ-EVAL-002 — `AccessRequest` constructor + chained setters

```rust
/// A point-check request. Chained setters keep the API open for future
/// fields (e.g. environment attributes) without breaking changes (epic R9).
#[derive(Debug, Clone)]
pub struct AccessRequest {
    subject_attrs: HashMap<String, HashSet<String>>,
    operation: String,
    resource_type: String,
    resource_attrs: HashMap<String, HashSet<String>>,
}

impl AccessRequest {
    /// Required fields up front; attribute maps default to empty (fail-closed).
    pub fn new(operation: impl Into<String>, resource_type: impl Into<String>) -> Self;
    /// Sets the subject's attributes (consuming setter).
    pub fn subject_attrs(self, attrs: HashMap<String, HashSet<String>>) -> Self;
    /// Sets the resource's attributes (consuming setter).
    pub fn resource_attrs(self, attrs: HashMap<String, HashSet<String>>) -> Self;
}
```

There is **no** `.build()` method. Fields are private. Attribute maps are multi-valued `HashMap<String, HashSet<String>>` per D18.

**Acceptance criteria:**
- `AccessRequest::new("read", "job")` compiles and yields empty attribute maps.
- `AccessRequest::new("read", "job").subject_attrs(s).resource_attrs(r)` compiles in any setter order.
- An `AccessRequest` without an operation or resource type is unrepresentable (compile-time).

**Test obligations:** covered implicitly by the evaluate tests; one test exercising default-empty maps (fail-closed: empty subject attrs against a non-`All` graph → `Deny`).

#### REQ-EVAL-003 — `evaluate()` signature and core algorithm

```rust
pub fn evaluate(view: &impl PolicyView, request: &AccessRequest) -> Decision;
```

Algorithm (exact; per D16 this is the epic's original `evaluate()`, unchanged):

```
1. uas ← view.matching_uas(request.subject_attrs)
2. for ua in uas, for assoc in view.associations_for_ua(ua.id):
     a. if !assoc.operations.contains(request.operation): continue
     b. match assoc.target:
        - ObjectAttribute(oa_id):
            if view.get_oa(oa_id) is Some(oa)
               and oa.resource_type == request.resource_type
               and oa.matcher.matches(request.resource_attrs)
            → return Decision::Allow
        - PolicyClass(pc_id):
            if any oa in view.oas_for_pc(pc_id, request.resource_type)
               has oa.matcher.matches(request.resource_attrs)
            → return Decision::Allow
3. return Decision::Deny
```

**Acceptance criteria / test obligations (each is a distinct test):**
- Allow via UA→OA: matching UA, association with the operation, OA with matching `resource_type` and matcher → `Allow`.
- Deny when the operation is absent from the association's operation set.
- Deny when no UA matches the subject attributes.
- Deny on `resource_type` mismatch between the OA and the request.
- Deny when the OA's matcher does not match the resource attributes.
- Multi-valued subject (D18): a subject with `org_id ∈ {alpha, beta}` is allowed through an alpha-scoped UA→OA path.
- `All`-matcher UA matches an **empty** subject attribute map (documented sharp edge, see REQ-DOC-001) — test asserts `Allow` for the public-resource pattern with empty subject attrs.

#### REQ-EVAL-004 — `evaluate()` UA→PC path keeps the OA-matcher check (D16)

On the `PolicyClass(pc_id)` branch, `evaluate()` MUST require that at least one OA returned by `view.oas_for_pc(pc_id, request.resource_type)` has `oa.matcher.matches(request.resource_attrs)`. Mere existence of OAs under the PC is NOT sufficient. (This rejects the review's "Fix" for Q1 in favour of the approved Option B; `scope()` is amended instead — see REQ-SCOPE-004/005.)

**Acceptance criteria / test obligations:**
- Allow via UA→PC: OA under the PC matches both resource type and resource attributes → `Allow`.
- **The review's counterexample, locked in as a test**: `(org_admins, org_alpha_pc, {read})`, `alpha_jobs { resource_type: "job", matcher: Matching { key: "org_id", values: ["alpha"] } }` assigned to `org_alpha_pc`; request for a job with `org_id: "beta"` → `Deny`.
- Deny when the PC has no OA for the requested resource type (fail-closed).

#### REQ-EVAL-005 — Dangling OA references fail closed

If `view.get_oa(oa_id)` returns `None` for a UA→OA association target, that association MUST be skipped (it can never produce `Allow`). No panic, no error.

**Acceptance criteria / test obligations:** a test with an association targeting a nonexistent OA ID asserts `Deny` (when no other path grants access).

### Feature 4 — PEP Scope

#### REQ-SCOPE-001 — `ScopeRequest` constructor + chained setter

```rust
/// A scope-resolution request for list-query filter injection.
#[derive(Debug, Clone)]
pub struct ScopeRequest {
    subject_attrs: HashMap<String, HashSet<String>>,
    operation: String,
    resource_type: String,
}

impl ScopeRequest {
    /// Required fields up front; subject attributes default to empty (fail-closed).
    pub fn new(operation: impl Into<String>, resource_type: impl Into<String>) -> Self;
    /// Sets the subject's attributes (consuming setter).
    pub fn subject_attrs(self, attrs: HashMap<String, HashSet<String>>) -> Self;
}
```

No `.build()`. Fields private. Same rationale and criteria as REQ-EVAL-002.

**Acceptance criteria:** `ScopeRequest::new("read", "job").subject_attrs(s)` compiles; operation/resource-type-less requests are unrepresentable.

#### REQ-SCOPE-002 — `ScopeConstraint` and `AccessScope` types

```rust
/// One attribute constraint for list-query filter injection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeConstraint {
    /// The resource's attribute `key` must have a value in `values`
    /// (translates to SQL `key IN (values...)`).
    Attribute {
        /// The resource attribute key to filter on.
        key: String,
        /// The acceptable values for that key.
        values: Vec<String>,
    },
}

/// The resolved access scope for a (subject, operation, resource_type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessScope {
    /// No filter needed — subject may access all resources of this type.
    Unrestricted,
    /// OR-combined constraints (a union of access paths, never an intersection).
    Constrained(Vec<ScopeConstraint>),
    /// No access — the application should return an empty result set.
    None,
}
```

**Acceptance criteria:** public, rustdoc'd, derives exactly as above; the `Constrained` rustdoc carries the union note (REQ-DOC-002).

#### REQ-SCOPE-003 — `scope()` signature and candidate-OA collection

```rust
pub fn scope(view: &impl PolicyView, request: &ScopeRequest) -> AccessScope;
```

Algorithm steps 1–2 (collection; amended per D16):

```
1. uas ← view.matching_uas(request.subject_attrs)
2. candidate_oas ← []
   for ua in uas, for assoc in view.associations_for_ua(ua.id):
     a. if !assoc.operations.contains(request.operation): continue
     b. match assoc.target:
        - ObjectAttribute(oa_id):
            if view.get_oa(oa_id) is Some(oa)
               and oa.resource_type == request.resource_type
            → push oa onto candidate_oas
        - PolicyClass(pc_id):
            → push all of view.oas_for_pc(pc_id, request.resource_type)
              onto candidate_oas
```

UA→PC targets are **expanded into their OAs** — `scope()` MUST NOT return `Unrestricted` merely because a UA→PC association exists with OAs of the resource type. Dangling OA references are skipped (fail-closed), mirroring REQ-EVAL-005.

**Acceptance criteria / test obligations:**
- **The review's counterexample, locked in as a test**: the REQ-EVAL-004 fixture (`(org_admins, org_alpha_pc, {read})` with `alpha_jobs { org_id ∈ [alpha] }` under the PC) yields `Constrained([Attribute { key: "org_id", values: ["alpha"] }])`, **not** `Unrestricted`.
- Associations whose operation set lacks the requested operation contribute nothing.
- A dangling UA→OA reference contributes nothing (and yields `None` if it is the only path).

#### REQ-SCOPE-004 — `All`-matcher short-circuit to `Unrestricted` (D17)

After collection (step 3): if any OA in `candidate_oas` has `matcher == AttributeMatcher::All`, `scope()` MUST return `AccessScope::Unrestricted` immediately, regardless of any other constraints collected.

**Acceptance criteria / test obligations:**
- `Unrestricted` via an `All`-matcher OA reached through a direct UA→OA association (public-resources pattern).
- `Unrestricted` via an `All`-matcher OA assigned to a PC reached through a UA→PC association (platform-admin pattern).
- A mix of one `All`-matcher OA and several `Matching` OAs still returns `Unrestricted` (not `Constrained`).

#### REQ-SCOPE-005 — Constraint merging: same-key value union, dedup, first-seen order

Steps 4–5: from the remaining `Matching { key, values }` matchers, build constraints grouped by `key`:

```
4. constraints ← for each distinct key (in first-seen order):
     values ← union of all values for that key, deduplicated,
              preserving first-seen order
     → ScopeConstraint::Attribute { key, values }
5. if constraints is empty → return AccessScope::None
   else → return AccessScope::Constrained(constraints)
```

Merging same-key constraints by value-union is semantically exact: `(k ∈ V₁) OR (k ∈ V₂) ⇔ k ∈ V₁ ∪ V₂`. Distinct keys remain separate OR-combined constraints. "First-seen order" applies to both the key ordering of the constraint list and the value ordering within each constraint, making outputs deterministic for a given iteration order of `candidate_oas`.

**Acceptance criteria / test obligations:**
- Two OAs `{ org_id ∈ [alpha] }` and `{ org_id ∈ [beta] }` → one constraint `Attribute { key: "org_id", values: ["alpha", "beta"] }`.
- Duplicate values across OAs appear once (`[alpha] ∪ [alpha, beta]` → `["alpha", "beta"]`).
- Two OAs with distinct keys (`org_id`, `id`) → two constraints, OR-combined.
- Specific-object pattern: an OA `{ key: "id", values: [resource_id] }` yields `Constrained([Attribute { key: "id", values: [resource_id] }])`.

#### REQ-SCOPE-006 — `AccessScope::None` on no grant

When no UA matches, or no association carries the operation, or no candidate OA of the resource type is reachable, `scope()` MUST return `AccessScope::None` (never an empty `Constrained(vec![])`).

**Acceptance criteria / test obligations:** tests for each empty-path cause: no matching UA; operation absent; resource type with no OAs; PC with no OAs of the type.

### Cross-cutting invariant

#### REQ-INV-001 — `evaluate()`/`scope()` soundness invariant (tested, not just asserted)

For any policy graph, subject attributes, operation, and resource type: a resource's attributes satisfy the output of `scope()` (i.e., the resource is admitted by `Unrestricted`, matches at least one constraint of `Constrained`, or never for `None`) **if and only if** `evaluate()` returns `Allow` for that resource.

**Acceptance criteria / test obligations:** a dedicated test module with shared fixtures covering at minimum the five canonical patterns — platform admin (`All` OA under platform PC), org-scoped admin (UA→PC to an org PC with `Matching` OAs), org member (UA→OA), specific object (`key: "id"`), public resource (`All` UA → `All` OA) — that, for each fixture, enumerates a representative resource set (in-scope and out-of-scope attribute maps) and asserts for every resource: `resource admitted by scope(view, sreq)` ⇔ `evaluate(view, areq) == Allow`. The test includes a helper that interprets an `AccessScope` against a resource attribute map (`Unrestricted` → true; `Constrained(cs)` → any constraint where the resource's value-set for `key` **intersects** `values` (D18); `None` → false).

### Documentation requirements

#### REQ-DOC-001 — `AttributeMatcher::All` unauthenticated-match warning

The rustdoc of `AttributeMatcher::All` in `lib.rs` MUST warn that an `All`-matcher UA matches the **empty attribute map** — i.e., unauthenticated subjects. Sentinel cannot distinguish "no attributes sent" from "unauthenticated"; applications MUST enforce authentication before calling `evaluate()`/`scope()` for non-public resources.

**Acceptance criteria:** rustdoc present on the `All` variant; the corresponding sharp-edge test from REQ-EVAL-003 exists.

#### REQ-DOC-002 — `AccessScope::Constrained` is a union

The rustdoc of `AccessScope::Constrained` MUST state that constraints are a **union** (OR) of access paths, never an intersection — multi-axis "AND" policies (e.g., "org alpha AND low-sensitivity") are not expressible and would broaden access if attempted via multiple associations.

**Acceptance criteria:** rustdoc present on the variant.

#### REQ-DOC-003 — Audit-trail boundary note

The epic's architecture notes MUST state that sentinel's event log audits *policy* history only; reconstructing per-subject effective-access history ("what could alice access on June 1st?") additionally requires the consuming application's own membership/attribute history.

**Acceptance criteria:** note added to `docs/2602181244_epic_sentinel_library.typ`.

#### REQ-DOC-004 — Upstream document amendments

- `docs/2602181244_epic_sentinel_library.typ`: amend R3 and the Feature 4 `scope()` algorithm per D16/D17; add decision rows D16–D20 to the design-decisions table; add the REQ-DOC-003 note.
- `docs/2602182248_spec_policy_aggregate.md`: append an amendment note recording D19 (association upsert; "Commands Mirror Events" semantics now "set the operation set") and D20 (`PolicyApplyError` is now inhabited; "Infallible apply" decision superseded).

**Acceptance criteria:** both documents updated in the same change set as the code; no stale claims of `Unrestricted`-on-existence, duplicate-append association semantics, or infallible `apply` remain.

---

## Requirement Traceability

| Requirement | Source decision / epic req | Review finding |
|---|---|---|
| REQ-HARD-001, REQ-HARD-002 | D19 | Q4 (association identity) |
| REQ-HARD-003 | D20 | Q5 / `aggregate.rs:296` |
| REQ-HARD-004 | D18 (amended: multi-valued sets) | Q3 (single-value limitation) |
| REQ-EVAL-001…003 | Epic R6, R9; D18 | — |
| REQ-EVAL-004 | D16 (Option B) | Q1 (UA→PC inconsistency) |
| REQ-EVAL-005 | Fail-closed principle (epic R4/D15) | — |
| REQ-SCOPE-001, 002 | Epic R7, R9; D12; D18 | — |
| REQ-SCOPE-003 | D16 (amends epic R3 / Feature 4 algorithm) | Q1 |
| REQ-SCOPE-004 | D17 | Q2 (`All` OA gap) |
| REQ-SCOPE-005, 006 | Epic R7; D12 | — |
| REQ-INV-001 | D16 + D17 (soundness invariant) | Q1, Q2 |
| REQ-DOC-001 | — | Q5a |
| REQ-DOC-002 | D12 | Q5b |
| REQ-DOC-003 | D5 (no U nodes) | Q5c |
| REQ-DOC-004 | D16–D20 | all |

---

## Core API Summary

All new code in `sentinel_core/src/lib.rs` (single file until the split threshold is reached). Full type definitions are in the requirements above; the two entry points:

```rust
pub fn evaluate(view: &impl PolicyView, request: &AccessRequest) -> Decision;
pub fn scope(view: &impl PolicyView, request: &ScopeRequest) -> AccessScope;
```

Both are free functions, generic over `&impl PolicyView` (epic R5/D13) — never tied to `PolicyGraph` directly.

---

## Files to Modify

| File | Change | Requirements |
|---|---|---|
| `sentinel_core/src/lib.rs` | Change `AttributeMatcher::matches` and `PolicyView::matching_uas` to `&HashMap<String, HashSet<String>>` and migrate existing tests (REQ-HARD-004). Add `Decision`, `AccessRequest`, `ScopeRequest`, `ScopeConstraint`, `AccessScope`, `evaluate()`, `scope()` + tests. Change `add_association` to upsert and update its (and `remove_association`'s) rustdoc; rewrite the two duplicate-asserting tests. Add `All`-matcher rustdoc warning. | REQ-HARD-001/004, REQ-EVAL-*, REQ-SCOPE-*, REQ-INV-001, REQ-DOC-001/002 |
| `sentinel_core/src/aggregate.rs` | Replace `event.data.as_ref().unwrap()` (line 296) with an error return; add `PolicyApplyError::MissingEventData`; update `PolicyApplyError` and `CreateAssociation` rustdoc; add the replay test and the missing-data test. | REQ-HARD-002, REQ-HARD-003 |
| `docs/2602181244_epic_sentinel_library.typ` | Amend Feature 4 scope() algorithm and R3; add decision rows D16–D20; add audit-trail note. | REQ-DOC-003, REQ-DOC-004 |
| `docs/2602182248_spec_policy_aggregate.md` | Append amendment note for D19/D20. | REQ-DOC-004 |

New dependencies: **none**.

---

## Test Plan Summary (TDD order detailed in the implementation plan)

1. **Hardening** (REQ-HARD-001…004): multi-valued matcher signature migration with intersection/disjoint/empty-set tests (foundational — first); association upsert (replace, not duplicate); replay scenario from the review (create/create/remove → that grant fully absent, others intact); `apply` with `None` event data returns `MissingEventData`.
2. **evaluate()** (REQ-EVAL-001…005): allow via UA→OA; allow via UA→PC (OA under PC matches); deny when operation missing; deny when no UA matches; deny on resource-type mismatch; deny when OA under PC does **not** match resource attrs (review counterexample — locks in Option B); dangling OA reference → deny; `All` UA + empty subject attrs → allow on public OA (sharp edge).
3. **scope()** (REQ-SCOPE-001…006): `Unrestricted` via `All` OA through UA→OA; `Unrestricted` via `All` OA under a PC; mixed `All`+`Matching` → `Unrestricted`; `Constrained` from UA→PC expansion (review counterexample yields `org_id ∈ [alpha]`, **not** `Unrestricted`); same-key value merging with dedup and order; multi-key OR combination; specific-object `id` constraint; `None` for each empty-path cause.
4. **Consistency** (REQ-INV-001): shared fixtures for the five canonical patterns, enumerating resources through both functions with a scope-interpretation helper.

Exit criteria: `cargo test` green (existing 153 tests, two rewritten for D19, plus the new tests above), `cargo clippy -- -D warnings` clean, `cargo fmt` clean, `#![deny(missing_docs)]` satisfied for all new public items.

---

## Out of Scope

- Feature 5 integration tests (separate spec; builds on this one)
- Feature 6 derive macros, Feature 7 facade polish
- UA→UA / OA→OA / PC→PC hierarchy
- `Any`/`All` nesting in `ScopeConstraint`; environmental attributes
- Reverse indexes / performance work on `PolicyView` queries
- Duplicate-ID validation for `Create{UA,OA,PC}` commands (existing insert-or-overwrite semantics retained and documented)
- `RemoveAssociation` variants targeting individual operations (D19 makes the operation set atomic per grant)

---

## Expected Outcome

- `evaluate()` and `scope()` are implemented, documented, and consistent by construction (D16/D17), with the soundness invariant covered by tests (REQ-INV-001).
- The platform-admin (`All` OA under platform PC), org-scoped admin (UA→PC to an org PC), org-member (UA→OA), specific-object (`key: "id"`), and public-resource (`All` UA → `All` OA) patterns behave correctly in **both** PEP functions.
- The aggregate has no library-code `unwrap()` and a coherent association identity; replaying any event log yields the same graph as live application.
