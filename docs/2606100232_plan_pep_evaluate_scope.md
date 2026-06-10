# Delivery Plan 2606100232 — PEP Evaluate & Scope

- **Status**: Draft — awaiting developer approval
- **Created**: 2026-06-10
- **Implements spec**: `docs/2606100155_spec_pep_evaluate_scope.md` (Approved 2026-06-10)
- **Crate(s)**: `sentinel_core` (+ doc amendments to the epic and Feature 2 spec)
- **Baseline**: 153 tests passing, clippy clean, `cargo fmt --check` clean, working tree clean on `main`

---

## Implementation Plan

The table below is the canonical phase list parsed by the spec pipeline
(`/implement`). Detailed per-phase TDD breakdowns follow in §4–§8.

| Phase | Focus | Effort |
|-------|-------|--------|
| Phase 1 | Multi-valued attribute matching foundation — set-intersection semantics for subject/resource attributes (REQ-HARD-004, D18) | 0.5 day |
| Phase 2 | Aggregate and graph hardening — association upsert identity, event-replay coherence, fallible event application (REQ-HARD-001…003) | 0.5 day |
| Phase 3 | PEP point-check authorization — Decision, AccessRequest, and evaluate() over PolicyView (REQ-EVAL-001…005) | 1 day |
| Phase 4 | PEP scope resolution — AccessScope, ScopeConstraint, ScopeRequest, and scope() for list-query filter injection (REQ-SCOPE-001…006) | 1 day |
| Phase 5 | Soundness invariant verification and final documentation sweep — evaluate/scope consistency across canonical patterns (REQ-INV-001, REQ-DOC-003/004) | 0.5 day |

---

## 1. Purpose & Scope

This plan sequences the implementation of the approved spec's 21 requirements into
five TDD phases, each ending in a fully green tree. It exists to make the
ordering constraints explicit, pin the failing tests that open each phase, and
map work onto Conventional Commits.

**Requirements covered (all 21):**

- Hardening: `REQ-HARD-001`, `REQ-HARD-002`, `REQ-HARD-003`, `REQ-HARD-004`
- Feature 3 — evaluate: `REQ-EVAL-001…005`
- Feature 4 — scope: `REQ-SCOPE-001…006`
- Cross-cutting invariant: `REQ-INV-001`
- Documentation: `REQ-DOC-001`, `REQ-DOC-002`, `REQ-DOC-003`, `REQ-DOC-004`

**Not in this plan** (per spec "Out of Scope"): Feature 5 integration tests,
Feature 6 derive macros, Feature 7 facade, hierarchy traversal, `Any`/`All`
nesting in constraints, reverse indexes / perf, duplicate-ID validation,
operation-targeted `RemoveAssociation`.

---

## 2. Global Constraints (apply to every phase)

These are non-negotiable gates. **No phase may leave the tree red.**

- **G1 — Green gate (phase exit):** all three must pass before a phase is
  considered done:
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo fmt --all -- --check`
- **G2 — TDD discipline:** each phase opens with one or more *failing* tests
  (named below), then minimal implementation, then refactor. Commits may bundle
  test+impl but the working sequence is red → green → clean.
- **G3 — Library hygiene:** no `unwrap()`/`expect()` in non-test code; rustdoc on
  every new public item; `#![deny(missing_docs)]` (already enabled in
  `lib.rs`) must remain satisfied.
- **G4 — Doc co-landing:** an upstream document amendment lands **in the same
  phase** as the code that makes its old claim stale (see per-phase doc tasks
  and §8). No phase may merge code that contradicts an unamended upstream doc.
- **G5 — Commit hygiene:** Conventional Commits with scopes from
  {`core`, `derive`, `graph`, `pep`, `scope`}; each commit references its
  `REQ-*`/`D*` IDs in the body.

---

## 3. Phase Dependency Graph

```
Phase 1 (REQ-HARD-004, multi-valued sigs)  ──┐
                                              ├──> Phase 3 (evaluate) ──┐
Phase 2 (REQ-HARD-001/002/003, aggregate)  ──┘                          ├──> Phase 5 (invariant + epic docs)
                                              └──> Phase 4 (scope) ──────┘
```

- **Phase 1 is foundational** (signature migration) and must precede Phases 3 & 4
  because the request types build on `&HashMap<String, HashSet<String>>`.
- **Phase 2** (aggregate coherence) is independent of Phase 1 but must precede the
  PEP phases so the storage layer the PEP reads from is coherent. Ordered after
  Phase 1 to retire the highest-churn change first.
- **Phase 3 and Phase 4** both depend only on Phase 1 and are mutually
  independent; they may proceed in either order or in parallel.
- **Phase 5** depends on **both** Phase 3 and Phase 4 (the invariant test
  exercises `evaluate()` and `scope()` together).

---

## 4. Phase 1 — Multi-Valued Attribute Foundation

> **Why first:** `REQ-HARD-004` is foundational *and* the highest-churn change
> (it migrates the signatures of `AttributeMatcher::matches` and
> `PolicyView::matching_uas`, rippling through ~10 existing call sites / tests in
> `lib.rs`). Retiring it first means every later phase builds on the final
> signatures and never re-touches migrated tests.

### Goal
Migrate attribute matching from single-valued (`&HashMap<String, String>`) to
multi-valued (`&HashMap<String, HashSet<String>>`) with non-empty-intersection
semantics (D18), leaving the tree green.

### Scope (REQ IDs)
- `REQ-HARD-004` (signature + semantics migration)
- `REQ-DOC-004` (partial): add the **D18** decision row to the epic's
  design-decisions table (the attribute model claim becomes stale here).

### TDD tasks
1. **Red — new/rewritten matcher tests** (`lib.rs` tests module). Add unit tests
   for the new semantics, written against the new signature so they fail to
   compile/assert first:
   - intersection match: subject `org_id ∈ {alpha, beta}` vs
     `Matching { key: "org_id", values: ["alpha"] }` → `true`.
   - disjoint no-match: subject `org_id ∈ {gamma}` → `false`.
   - empty-set no-match: `org_id → {}` behaves like an absent key → `false`.
   - `All` unchanged: matches empty map and any map.
2. **Green — change `AttributeMatcher::matches`** to take
   `&HashMap<String, HashSet<String>>` using the exact body in `REQ-HARD-004`
   (`vs.iter().any(|v| values.contains(v))`). Update its rustdoc to describe
   intersection semantics and the empty-set fail-closed rule.
3. **Green — change `PolicyView::matching_uas`** (trait at `lib.rs:139` and the
   `PolicyGraph` impl at `lib.rs:266`) to
   `subject_attrs: &HashMap<String, HashSet<String>>`.
4. **Migrate existing call sites** (the ~10 `.matches(`/`matching_uas(` test
   sites flagged at `lib.rs` ~780, 819–833, 852, 874, 1304, 1323–1469, 1872–1898):
   convert single-valued literals to semantics-equivalent single-element
   `HashSet`s (e.g., `HashMap::from([("org_id".into(), HashSet::from(["alpha".into()]))])`).
   Preserve the existing assertions' intent.
5. **Doc** — add the **D18** row to the epic's design-decisions table
   (`REQ-DOC-004`, attribute-model portion).
6. **Refactor** — extract a small test helper (e.g., `attrs([(k, [v, …])])`) if
   the migration churn warrants it; keep it test-only.

### Exit criteria (observable)
- `AttributeMatcher::matches` and `PolicyView::matching_uas` both take
  `&HashMap<String, HashSet<String>>` (verifiable by signature grep / compile).
- The four new semantics tests pass; all migrated existing tests pass.
- G1 (test/clippy/fmt) green; G3 satisfied.
- Epic table contains a D18 row.

### Dependencies
None (operates on existing Feature 1 code).

### Suggested commits
- `refactor(graph)!: multi-valued attribute matching via HashSet intersection (REQ-HARD-004, D18)`
  - Body: notes the breaking signature change to `matches`/`matching_uas`,
    intersection + empty-set-fail-closed semantics, and the migrated tests.
- `docs(core): record D18 (multi-valued request attributes) in epic (REQ-DOC-004)`
  - (May be folded into the commit above to keep the doc co-landed.)

---

## 5. Phase 2 — Aggregate & Graph Hardening

### Goal
Make association identity coherent under replay (upsert on `(ua_id, target)`)
and remove the library-code `unwrap()` in `apply()`, with the Feature 2 spec
amended in the same change set.

### Scope (REQ IDs)
- `REQ-HARD-001` (association upsert; rustdoc on `add_association` /
  `remove_association`)
- `REQ-HARD-002` (replay coherence; `CreateAssociation` rustdoc)
- `REQ-HARD-003` (`PolicyApplyError::MissingEventData`; remove `unwrap()` at
  `aggregate.rs:296`)
- `REQ-DOC-004` (partial): aggregate-spec amendment note (D19/D20) and epic
  decision rows D19, D20.

### TDD tasks

**Track A — association upsert (REQ-HARD-001/002):**
1. **Red — rewrite the two duplicate-asserting tests** in `lib.rs`
   (`add_association_duplicate_creates_two_entries` ~line 1021 and
   `add_association_same_target_different_ops_creates_two` ~line 1043) to assert
   **replacement**: after the second add, exactly **one** association exists for
   the `(ua_id, target)` pair, carrying the **second** operation set. Add a test
   asserting distinct-target / distinct-UA adds still accumulate.
2. **Red — aggregate replay test** in `aggregate.rs`: replay
   `AssociationCreated(ua,t,{read})` → `AssociationCreated(ua,t,{write,delete})`
   → `AssociationRemoved(ua,t)` via `apply` and assert **no** association for
   `(ua,t)`; replay only the first two and assert exactly one with
   `{write, delete}`; assert a different-target association on the same UA is
   untouched.
3. **Green — `PolicyGraph::add_association`**: before pushing, remove any
   existing association with the same `(ua_id, target)` (retain-then-push, or
   replace-in-place). Update its rustdoc to the upsert contract; update
   `remove_association` rustdoc to drop the "may be multiple matching entries"
   wording (now at most one).
4. **Doc** — `CreateAssociation` command rustdoc in `aggregate.rs`: document
   "set the operation set for this grant" (upsert) semantics.

**Track B — apply error (REQ-HARD-003):**
5. **Red — missing-data test** in `aggregate.rs`: construct an
   `Event<PolicyEvent>` with `data: None` and assert
   `apply(...) == Err(PolicyApplyError::MissingEventData(event.id))` (no panic).
6. **Green — inhabit `PolicyApplyError`** (currently `enum PolicyApplyError {}`
   at `aggregate.rs:225`) with the `MissingEventData(Uuid)` variant exactly as in
   `REQ-HARD-003`; replace `event.data.as_ref().unwrap()` at `aggregate.rs:296`
   with `.ok_or(PolicyApplyError::MissingEventData(event.id))?`. Update the
   enum's rustdoc (drop "uninhabited / infallible"; add the purge-semantics note
   that purging policy events is unsupported and fails replay closed).

**Track C — upstream docs (co-landing, REQ-DOC-004):**
7. Append an amendment note to `docs/2602182248_spec_policy_aggregate.md`
   recording D19 (association upsert; "Commands Mirror Events" → "set the
   operation set") and D20 (`PolicyApplyError` now inhabited; "Infallible apply"
   superseded).
8. Add D19 and D20 rows to the epic's design-decisions table.

### Exit criteria (observable)
- Exactly one association per `(ua_id, target)` after repeated adds; second add's
  operation set wins (verified by the rewritten tests).
- Three-event replay yields no association for the pair; two-event replay yields
  one `{write, delete}` association; sibling associations intact.
- `apply` with `data: None` returns `MissingEventData(event.id)`; no `unwrap()`/
  `expect()` remains in non-test code of `aggregate.rs` or `lib.rs` (grep-verifiable).
- Feature 2 spec carries the D19/D20 amendment note; epic table has D19/D20 rows.
- G1 green; G3 satisfied.

### Dependencies
Independent of Phase 1; scheduled after it. Must complete before Phases 3 & 4.

### Suggested commits
- `fix(graph): upsert association identity (ua_id, target) (REQ-HARD-001, REQ-HARD-002, D19)`
  - Includes graph upsert, rewritten duplicate tests, aggregate replay test,
    `CreateAssociation`/`add_association`/`remove_association` rustdoc, and the
    Feature 2 spec D19 note.
- `fix(core): return MissingEventData instead of unwrap in apply (REQ-HARD-003, D20)`
  - Includes the inhabited `PolicyApplyError`, the `ok_or` change, the
    missing-data test, rustdoc, and the Feature 2 spec D20 note.
- `docs(core): record D19/D20 in epic decision table (REQ-DOC-004)`
  - (May be folded into the two `fix` commits to keep docs co-landed per G4.)

---

## 6. Phase 3 — PEP Evaluate (Feature 3)

### Goal
Implement the `Decision` type, `AccessRequest`, and the `evaluate()` free
function with the Option-B UA→PC matcher check and fail-closed dangling-OA
handling.

### Scope (REQ IDs)
- `REQ-EVAL-001` (`Decision`)
- `REQ-EVAL-002` (`AccessRequest` constructor + chained setters)
- `REQ-EVAL-003` (`evaluate()` signature + core algorithm)
- `REQ-EVAL-004` (UA→PC keeps the OA-matcher check; review counterexample)
- `REQ-EVAL-005` (dangling OA references fail closed)
- `REQ-DOC-001` (`AttributeMatcher::All` unauthenticated-match warning)

### TDD tasks
1. **Red — type-shape tests** for `AccessRequest`: `new("read","job")` yields
   empty (multi-valued) attribute maps; `.subject_attrs(s).resource_attrs(r)`
   compiles in any order. (Mostly compile-time; one runtime fail-closed test:
   empty subject attrs against a non-`All` graph → `Deny`.)
2. **Red — evaluate behavior tests** (each a distinct test per REQ-EVAL-003/004/005):
   - Allow via UA→OA (matching UA + operation + OA resource_type + matcher).
   - Deny when operation absent from association's set.
   - Deny when no UA matches.
   - Deny on OA/request resource_type mismatch.
   - Deny when OA matcher doesn't match resource attrs.
   - Multi-valued subject (D18): `org_id ∈ {alpha, beta}` allowed via alpha OA.
   - `All`-matcher UA + **empty** subject attrs → `Allow` (REQ-DOC-001 sharp edge).
   - **Allow via UA→PC** (OA under PC matches type + attrs).
   - **Review counterexample (locked in):** `(org_admins, org_alpha_pc, {read})`,
     `alpha_jobs { resource_type:"job", matcher: Matching{key:"org_id", values:["alpha"]} }`
     under `org_alpha_pc`; request job with `org_id:"beta"` → `Deny`.
   - Deny when PC has no OA for the requested resource_type (fail-closed).
   - Dangling UA→OA reference (`get_oa` → `None`) → `Deny`.
3. **Green — define `Decision`** (REQ-EVAL-001) with the exact derives (no
   serde).
4. **Green — define `AccessRequest`** (REQ-EVAL-002): private fields,
   multi-valued maps, `new(operation, resource_type)`, consuming
   `subject_attrs`/`resource_attrs` setters, **no `.build()`**.
5. **Green — implement `evaluate(view: &impl PolicyView, request: &AccessRequest)
   -> Decision`** following the exact algorithm in REQ-EVAL-003, including the
   PC branch requiring `oas_for_pc(...).any(matcher.matches)` (REQ-EVAL-004) and
   skipping `None` OAs (REQ-EVAL-005).
6. **Doc** — add the `AttributeMatcher::All` warning rustdoc (REQ-DOC-001): an
   `All`-matcher UA matches the empty attribute map (unauthenticated subjects);
   apps must enforce auth before calling the PEP for non-public resources.
7. **Refactor** — share fixture builders within the test module; keep `evaluate`
   readable (helper for the per-association inner check is acceptable).

### Exit criteria (observable)
- `Decision`, `AccessRequest`, and `evaluate()` are public, rustdoc'd, and match
  the spec's exact signatures/derives.
- All REQ-EVAL-003/004/005 tests pass, including the locked-in review
  counterexample (`beta` job → `Deny`) and the empty-subject `All` sharp edge.
- `AttributeMatcher::All` rustdoc carries the unauthenticated-match warning.
- G1 green; G3 satisfied (`#![deny(missing_docs)]` holds for new items).

### Dependencies
Phase 1 (multi-valued signatures) and Phase 2 (coherent associations).

### Suggested commits
- `feat(pep): add Decision and AccessRequest types (REQ-EVAL-001, REQ-EVAL-002)`
- `feat(pep): implement evaluate() point check (REQ-EVAL-003, REQ-EVAL-004, REQ-EVAL-005, D16)`
  - Body locks in the Option-B UA→PC counterexample test.
- `docs(core): warn All matcher admits empty/unauthenticated subjects (REQ-DOC-001)`
  - (May be folded into the `evaluate()` commit since the sharp-edge test ships there.)

---

## 7. Phase 4 — PEP Scope (Feature 4)

### Goal
Implement `ScopeRequest`, `ScopeConstraint`, `AccessScope`, and the `scope()`
free function with UA→PC expansion (D16), `All`-matcher short-circuit (D17),
same-key value-union merging (first-seen order), and `None` on no grant.

### Scope (REQ IDs)
- `REQ-SCOPE-001` (`ScopeRequest`)
- `REQ-SCOPE-002` (`ScopeConstraint`, `AccessScope`)
- `REQ-SCOPE-003` (signature + candidate-OA collection with UA→PC expansion)
- `REQ-SCOPE-004` (`All`-matcher short-circuit to `Unrestricted`)
- `REQ-SCOPE-005` (constraint merging: same-key union, dedup, first-seen order)
- `REQ-SCOPE-006` (`AccessScope::None` on no grant)
- `REQ-DOC-002` (`AccessScope::Constrained` union note)
- `REQ-DOC-004` (partial): epic R3 amendment, Feature 4 `scope()` algorithm
  rewrite, epic decision rows D16/D17 (these claims become stale when `scope()`
  lands).

### TDD tasks
1. **Red — type-shape tests** for `ScopeRequest`
   (`new("read","job").subject_attrs(s)` compiles; no `.build()`).
2. **Red — scope behavior tests** (per REQ-SCOPE-003…006):
   - **Review counterexample (locked in):** the REQ-EVAL-004 fixture yields
     `Constrained([Attribute{key:"org_id", values:["alpha"]}])`, **not**
     `Unrestricted` (REQ-SCOPE-003).
   - Operation absent → contributes nothing.
   - Dangling UA→OA reference → contributes nothing (→ `None` if sole path).
   - `Unrestricted` via `All` OA through direct UA→OA (public-resources)
     (REQ-SCOPE-004).
   - `Unrestricted` via `All` OA under a PC through UA→PC (platform-admin)
     (REQ-SCOPE-004).
   - Mixed `All` + `Matching` OAs → `Unrestricted` (REQ-SCOPE-004).
   - Two OAs `{org_id∈[alpha]}` + `{org_id∈[beta]}` → one
     `Attribute{key:"org_id", values:["alpha","beta"]}` (REQ-SCOPE-005).
   - Duplicate values dedup to first-seen order (REQ-SCOPE-005).
   - Two distinct keys → two OR-combined constraints (REQ-SCOPE-005).
   - Specific-object `{key:"id", values:[id]}` → `Constrained([Attribute id])`
     (REQ-SCOPE-005).
   - `None` for each empty-path cause: no matching UA; operation absent;
     resource_type with no OAs; PC with no OAs of the type (REQ-SCOPE-006).
3. **Green — define `ScopeConstraint` and `AccessScope`** (REQ-SCOPE-002) with
   exact derives; `Constrained` rustdoc carries the union note (REQ-DOC-002).
4. **Green — define `ScopeRequest`** (REQ-SCOPE-001): private fields, multi-valued
   subject map, `new` + consuming `subject_attrs`, no `.build()`.
5. **Green — implement `scope(view, request) -> AccessScope`** following the exact
   five-step algorithm: collect candidate OAs (UA→OA direct + UA→PC expanded via
   `oas_for_pc`, skipping `None`) → if any candidate matcher is `All` return
   `Unrestricted` → merge `Matching` matchers by key (value union, dedup,
   first-seen order) → empty ⇒ `None`, else `Constrained`.
6. **Doc (co-landing, REQ-DOC-004):** amend the epic — rewrite R3 and the
   Feature 4 `scope()` algorithm to the D16 expansion model, and add D16/D17
   rows to the decision table. (These epic claims are made stale by step 5.)
7. **Refactor** — factor the candidate-collection step so it can be reused by the
   invariant tests if helpful; keep merging deterministic.

### Exit criteria (observable)
- `ScopeRequest`, `ScopeConstraint`, `AccessScope`, and `scope()` are public,
  rustdoc'd, and match the spec's exact signatures/derives.
- All REQ-SCOPE-003…006 tests pass, including the locked-in counterexample
  (`Constrained([org_id ∈ alpha])`, not `Unrestricted`) and both `All`
  short-circuit paths.
- `AccessScope::Constrained` rustdoc states constraints are a union (OR).
- Epic R3 and Feature 4 algorithm reflect D16; epic table has D16/D17 rows; no
  stale `Unrestricted`-on-existence claim remains.
- G1 green; G3 satisfied.

### Dependencies
Phase 1 (multi-valued signatures). Independent of Phase 3 but must precede
Phase 5.

### Suggested commits
- `feat(scope): add ScopeRequest, ScopeConstraint, AccessScope types (REQ-SCOPE-001, REQ-SCOPE-002, REQ-DOC-002)`
- `feat(scope): implement scope() with UA→PC expansion and All short-circuit (REQ-SCOPE-003, REQ-SCOPE-004, REQ-SCOPE-005, REQ-SCOPE-006, D16, D17)`
- `docs(core): amend epic R3 and Feature 4 scope() algorithm for D16/D17 (REQ-DOC-004)`
  - (Must land in this phase per G4; may be folded into the `scope()` commit.)

---

## 8. Phase 5 — Soundness Invariant & Final Doc Sweep

### Goal
Prove `evaluate()`/`scope()` agreement by test across the five canonical
patterns, and complete the remaining upstream documentation (audit-trail note).

### Scope (REQ IDs)
- `REQ-INV-001` (soundness invariant, tested)
- `REQ-DOC-003` (audit-trail boundary note in the epic)
- `REQ-DOC-004` (final): verify all epic/Feature-2 amendments are present and no
  stale claim remains.

### TDD tasks
1. **Red — invariant test module** with shared fixtures for the five canonical
   patterns:
   - platform admin (`All` OA under platform PC),
   - org-scoped admin (UA→PC to an org PC with `Matching` OAs),
   - org member (UA→OA),
   - specific object (`key:"id"`),
   - public resource (`All` UA → `All` OA).
   Add a helper that interprets an `AccessScope` against a resource attribute map
   (`Unrestricted` ⇒ true; `Constrained(cs)` ⇒ any constraint whose `values`
   intersect the resource's value-set for `key` (D18); `None` ⇒ false). For each
   fixture, enumerate an in-scope and out-of-scope resource set and assert, for
   every resource: `scope`-admits ⇔ `evaluate == Allow`. Tests fail until the
   helper + fixtures are correct against the implemented functions (they should
   pass immediately if Phases 3/4 are correct — any mismatch is a real soundness
   bug to fix).
2. **Doc — REQ-DOC-003:** add the audit-trail boundary note to the epic's
   architecture notes (event log audits *policy* history only; reconstructing
   per-subject effective access also needs the app's membership/attribute
   history).
3. **Doc sweep — REQ-DOC-004 closure:** confirm the epic contains all of
   D16–D20 rows + amended R3 + Feature 4 algorithm + audit note, and that
   `docs/2602182248_spec_policy_aggregate.md` has the D19/D20 amendment note.
   Fix any gap left by earlier phases.

### Exit criteria (observable)
- The invariant test module passes for all five patterns across in-scope and
  out-of-scope resources (`scope`-admits ⇔ `evaluate == Allow`).
- Epic has the audit-trail note; all D16–D20 rows present; Feature 4 algorithm
  and R3 amended; Feature 2 spec amendment note present.
- G1 green; G3 satisfied.

### Dependencies
Phase 3 **and** Phase 4.

### Suggested commits
- `test(pep): assert evaluate()/scope() soundness invariant across canonical patterns (REQ-INV-001)`
- `docs(core): add audit-trail boundary note and close D16–D20 amendments (REQ-DOC-003, REQ-DOC-004)`

---

## 9. Requirement → Phase Traceability

| Requirement | Phase | Suggested commit scope |
|---|---|---|
| REQ-HARD-004 | 1 | `graph` (+ `core` docs) |
| REQ-HARD-001 | 2 | `graph` |
| REQ-HARD-002 | 2 | `graph` |
| REQ-HARD-003 | 2 | `core` |
| REQ-EVAL-001 | 3 | `pep` |
| REQ-EVAL-002 | 3 | `pep` |
| REQ-EVAL-003 | 3 | `pep` |
| REQ-EVAL-004 | 3 | `pep` |
| REQ-EVAL-005 | 3 | `pep` |
| REQ-SCOPE-001 | 4 | `scope` |
| REQ-SCOPE-002 | 4 | `scope` |
| REQ-SCOPE-003 | 4 | `scope` |
| REQ-SCOPE-004 | 4 | `scope` |
| REQ-SCOPE-005 | 4 | `scope` |
| REQ-SCOPE-006 | 4 | `scope` |
| REQ-INV-001 | 5 | `pep` (test) |
| REQ-DOC-001 | 3 | `core` |
| REQ-DOC-002 | 4 | `scope`/`core` |
| REQ-DOC-003 | 5 | `core` |
| REQ-DOC-004 | 1, 2, 4, 5 (distributed per stale-claim co-landing) | `core` |

> **REQ-DOC-004 distribution (G4):** D18 row → Phase 1; aggregate-spec D19/D20
> note + epic D19/D20 rows → Phase 2; epic R3 + Feature 4 algorithm + D16/D17
> rows → Phase 4; audit-trail note + final consistency sweep → Phase 5.

---

## 10. Files Touched by Phase

| File | P1 | P2 | P3 | P4 | P5 |
|---|----|----|----|----|----|
| `sentinel_core/src/lib.rs` | sigs + tests | upsert + tests | eval types/fn + tests + All doc | scope types/fn + tests + union doc | invariant tests |
| `sentinel_core/src/aggregate.rs` | — | apply error + replay/missing-data tests + rustdoc | — | — | — |
| `docs/2602181244_epic_sentinel_library.typ` | D18 row | D19/D20 rows | — | R3 + scope() algo + D16/D17 rows | audit note + sweep |
| `docs/2602182248_spec_policy_aggregate.md` | — | D19/D20 amendment note | — | — | — |

No new dependencies in any phase.

---

## 11. Final Verification Checklist (all phases complete)

- [ ] `cargo test --workspace` green (baseline 153 + two rewritten duplicate
      tests now asserting replacement + all new HARD/EVAL/SCOPE/INV tests).
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `#![deny(missing_docs)]` satisfied for every new public item
      (`Decision`, `AccessRequest`, `ScopeRequest`, `ScopeConstraint`,
      `AccessScope`, `evaluate`, `scope`, `PolicyApplyError::MissingEventData`).
- [ ] No `unwrap()`/`expect()` in non-test code of `lib.rs` or `aggregate.rs`
      (grep-verified).
- [ ] `AttributeMatcher::matches` and `PolicyView::matching_uas` take
      `&HashMap<String, HashSet<String>>`.
- [ ] Exactly one association per `(ua_id, target)`; three-event replay erases
      only the intended grant.
- [ ] `apply` with `data: None` returns `MissingEventData(event.id)` (no panic).
- [ ] Review counterexample locked in **both** PEP functions: beta-org job →
      `evaluate` `Deny` **and** `scope` `Constrained([org_id ∈ alpha])` (not
      `Unrestricted`).
- [ ] `All`-matcher short-circuit verified for direct UA→OA and UA→PC paths.
- [ ] REQ-INV-001 invariant holds across all five canonical patterns.
- [ ] Epic amended: R3 + Feature 4 `scope()` algorithm + D16–D20 rows +
      audit-trail note; no stale `Unrestricted`-on-existence /
      duplicate-append / infallible-`apply` claims remain.
- [ ] Feature 2 spec (`2602182248`) carries the D19/D20 amendment note.
- [ ] Working tree clean; each commit follows Conventional Commits with a
      `core`/`graph`/`pep`/`scope` scope and references its `REQ-*`/`D*` IDs.
