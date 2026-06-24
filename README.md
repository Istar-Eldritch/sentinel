# Sentinel

> **Sentinel is the authorization engine where list queries are provably consistent with point checks, and every policy decision is auditable retroactively.**

An embeddable Rust authorization library implementing an intensional NGAC-inspired policy graph.

## Differentiators

### 1. Soundness by construction between check and filter

Every incumbent authorization engine (OPA, Cedar, Cerbos, SpiceDB) treats list-filtering as a *derived approximation* of the policy: they emit residual programs (Rego, CEL, partial-eval ASTs) that the application must interpret or reject. Approximation is unavoidable because their policy languages are Turing-complete.

Sentinel inverts the design: the matcher language is deliberately restricted so that the policy representation *is* the filter representation. `evaluate()` and `scope()` are two projections of the same `AttributeMatcher` set:

- `scope()` output translates to `key IN (values…)` exactly — no residuals, no escape hatch, no approximation.
- A resource admitted by `scope` constraints is **guaranteed** to be allowed by `evaluate`, and vice versa.
- This agreement is a **tested invariant**, not a best-effort claim. Property-based tests sweep arbitrary graph configurations and assert the biconditional holds for all of them.

The matcher vocabulary has three variants: `All` (wildcard — matches any resource), `Matching { key, values }` (value-set membership — `resource[key] ∩ values ≠ ∅`), and `Relative { resource_key, subject_key }` (co-membership — `resource[resource_key] ∩ subject[subject_key] ≠ ∅`, useful for same-org or same-team constraints without enumerating values in the policy graph).

*Give up Turing-complete policy expressiveness; gain provably exact query filters.* No shipping engine offers this as a guarantee.

### 2. Time-travel authorization

Because the policy graph is an [epoch](https://github.com/Istar-Eldritch/epoch) event stream, sentinel can reconstruct the exact policy state at any past instant and run the same authorization queries against it.

This answers questions no mainstream engine can answer as a first-class guarantee:

- *"Who **could have** accessed resource X at the time of the incident?"*
- *"Enumerate everything this contractor's grants could reach during their engagement."*
- *"Produce evidence for the Q1 access review as of the review date."*

API: `evaluate_at(t, req)`, `scope_at(t, req)`, `reachable_at(t, subject, vocabulary)`.

## NGAC lineage and intentional deviation

Sentinel implements the core [NGAC](https://csrc.nist.gov/publications/detail/sp/800-178/final) (Next Generation Access Control) graph model — User (U), User Attribute (UA), Object Attribute (OA), Policy Class (PC) nodes with assignment and association edges — but deviates from the NIST standard in one deliberate way: **resources are never stored in the graph**.

Instead, OA nodes carry attribute predicates (key + value set) that match resources at query time. This is *intensional* NGAC: the graph encodes *which resources belong to a scope* rather than enumerating them. The graph stays O(policies) regardless of data volume. NIST's reference implementation is O(resources); sentinel's design is O(policies).

### Sentinel vs. theoretical NGAC

| Capability | NGAC standard | Sentinel |
|---|---|---|
| Graph cardinality | O(resources) — objects are nodes | **O(policies)** — resources matched by predicate, never stored |
| List-query filter consistency | Not addressed | **Tested invariant** — `scope` output is provably consistent with `evaluate` |
| Policy audit / time-travel | Not addressed | **First-class** — event-sourced graph, full retroactive reconstruction |

### Sentinel vs. incumbents (on sentinel's differentiators)

This table covers only the dimensions where sentinel makes a specific claim. For everything else (policy expressiveness, multi-language support, tooling), established engines (Cedar, Cerbos, OPA, SpiceDB) are ahead.

| Capability | Cedar | Cerbos | OPA | SpiceDB | Sentinel |
|---|---|---|---|---|---|
| List-query filter | Partial eval (experimental, residual AST) | `PlanResources` (residual CEL, may return `CONDITIONAL`) | Partial eval (residual Rego) | Not applicable (tuple-based) | **Exact constraints, no residuals — proven consistent with point check** |
| Retroactive access audit | Decision logs only | Decision logs only | Decision logs only | Watch API (current state) | **Full policy reconstruction at any past timestamp** |

## Key Concepts

- **Attribute-matching model**: Resources are not nodes in the graph. OA nodes carry metadata about which resource attributes they match, keeping the graph small regardless of data volume.
- **NGAC graph**: 4 node types (User, User Attribute, Object Attribute, Policy Class) with assignment edges and association edges carrying access rights.
- **Two enforcement modes**: Point checks (`evaluate`) for command authorization; scope resolution (`scope`) for producing exact query filter constraints.
- **Event-sourced**: The policy graph is persisted via [epoch](https://github.com/Istar-Eldritch/epoch). Full audit trail, replay, and time-travel reconstruction are free.

## Crate Structure

| Crate | Description |
|-------|-------------|
| `sentinel_core` | Pure graph model, traits, PEP evaluation, scope resolution, time-travel |
| `sentinel_derive` | Proc macros for policy enforcement annotations |
| `sentinel` | Facade crate with feature-gated re-exports |

## Status

Early development. See `docs/` for design documents and `specs/` for implementation specifications.
