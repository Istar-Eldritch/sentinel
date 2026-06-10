# Sentinel Positioning: Differentiators & Roadmap Direction

**Date**: 2026-06-10
**Status**: Draft — awaiting developer review
**Inputs**: competitive landscape review (Cedar 4.6, Cerbos, OPA/regorus, SpiceDB/OpenFGA, casbin-rs, Oso)

---

## 1. Purpose

Sentinel's core (graph model, event-sourced aggregate, `evaluate()`, `scope()`) is implemented and tested (203 tests, soundness invariant verified). Before investing in the next tranche of features, this document fixes sentinel's competitive position and decides **what is worth building because it differentiates, versus what is catch-up work toward incumbents**.

## 2. Competitive Landscape Summary

| Capability | Sentinel today | Best alternative | Verdict |
|---|---|---|---|
| In-process Rust point check | `evaluate()` | Cedar (`cedar-policy`, formally verified, AWS-maintained) | Cedar stronger |
| Ownership/relative conditions | ✗ (static matchers) | Cedar `when { resource.owner == principal }`, Cerbos CEL | Incumbents stronger |
| Hierarchy / grouping | UA/OA/PC + assignments | Cedar entity parents | Comparable |
| Policy as runtime-mutable data | `PolicyCommand` → events | Cedar (policies are data), Zanzibar tuples | Comparable |
| Multi-language consumers | ✗ | Cedar (official `cedar-java` JNI), Cerbos (sidecar, many SDKs) | Incumbents stronger |
| List-query filter resolution | `scope()` → exact attribute constraints | Cerbos `PlanResources` (sidecar, residual CEL), OPA partial eval (residual Rego), Cedar partial eval (experimental) | **Sentinel stronger** — see §3.1 |
| Policy-change audit | Epoch event stream, replayable | Cerbos (git history), SpiceDB (Watch API), AVP (API logs) | **Sentinel stronger** — see §3.2 |
| Resource cardinality | O(policies) — resources never stored | Cedar same; Zanzibar O(resources) tuples | Comparable (Cedar) |

**Conclusion**: sentinel should not race incumbents on policy expressiveness, tooling, or language coverage. Its defensible position is the combination in §3.

## 3. Differentiators Worth Pursuing

### 3.1 Soundness by construction between check and filter ★ primary

Every incumbent treats list-filtering as a *derived approximation* of the policy: OPA and Cedar emit residual programs that must be (incompletely) translated to queries; Cerbos can return `CONDITIONAL` plans with arbitrary CEL ASTs the application must interpret or reject.

Sentinel inverts the design: the matcher language is deliberately restricted so that **the policy representation *is* the filter representation**. `evaluate()` and `scope()` are two projections of the same `AttributeMatcher` set:

- `scope()` output translates to `key IN (values...)` exactly — no residuals, no escape hatch, no approximation.
- The agreement between the two operations is a **tested invariant**: a resource is matched by `scope()` constraints *iff* `evaluate()` allows it.

**Thesis**: *give up Turing-complete policy expressiveness; gain provably exact query filters.* No shipping engine offers this as a guarantee.

**Mandate**: the soundness invariant is the project's north star. **Every future matcher or constraint extension must preserve it or be rejected.** This is a standing acceptance criterion, not a test.

### 3.2 Time-travel authorization ★ primary

Because the policy graph is an epoch event stream, sentinel can reconstruct the exact policy state at any past instant: replay events up to time T, then run `evaluate()`/`scope()` against the historical graph.

This answers questions no mainstream engine can:

- *"Who **could have** accessed resource X at the time of the incident?"* (decision logs only record what *was asked*)
- *"Enumerate everything this contractor's grants could reach during their engagement."*
- *"Produce evidence for the Q1 access review as of the review date."*

Paired with an event-sourced application, resource attributes are also reconstructible at T, enabling full retroactive access analysis — an evidence-grade capability for compliance regimes (SOC 2, ISO 27001, HIPAA access reviews, breach forensics).

**Candidate features**:
1. `PolicyState` reconstruction at timestamp/version (epoch replay bounded by event time) — mostly plumbing, epoch already replays.
2. `evaluate_at(view_at_t, request)` / `scope_at(...)` convenience APIs.
3. Retroactive enumeration helper: for a subject and time range, produce the set of `(operation, resource_type, constraints)` reachable — i.e., `scope()` swept over the operations vocabulary at T.

### 3.3 Obligations as event-sourced sagas (reactive policy) ★ secondary

NGAC's most distinctive feature — **obligations** (event-condition-action rules that mutate policy in response to events) — is the part of the standard nobody implements. Sentinel sits on the ideal substrate: an obligation is an epoch saga subscribing to decision/domain events and emitting `PolicyCommand`s.

Unlocks, with near-zero architectural novelty: break-glass access with auto-expiring grants; consent-driven grants (materialize on consent event, revoke on withdrawal); usage quotas ("after N exports, revoke").

Cedar has `forbid` but no obligations; Zanzibar tuples are passive. *NGAC obligations as sagas* would be a novel production artifact. Pursue **after** §3.1/§3.2 are consolidated and a concrete consumer use case exists.

### 3.4 Positional: the production-grade embeddable NGAC engine

There is no production-quality embeddable NGAC implementation (NIST's Policy Machine reference is academic Java). Sentinel's "intensional NGAC" (resources matched by predicate, never enumerated — O(policies) graph) is a tasteful deviation worth documenting against the standard. Zero extra work beyond accurate docs.

## 4. Consumer Guidance

- **Event-sourced Rust applications** are sentinel's natural primary consumers: in-process `evaluate()`/`scope()`, policy persistence on the epoch backends the application already runs, and §3.2 capabilities compounding when domain state is also replayable.
- **Non-Rust applications** should not adopt sentinel through bespoke bindings or service wrappers today. Incumbent engines (e.g., Cedar via its official Java bindings, or a Cerbos sidecar) cover point-check needs well. Revisit sentinel when §3.2 matures — compliance-heavy domains needing evidence-grade retroactive access analysis are the natural adopters, and that would be adoption *for* the differentiators rather than despite the integration cost.

## 5. Roadmap Order

1. **Consolidate §3.1**: promote the soundness invariant to documented contract (rustdoc + spec amendment); add property-based tests sweeping matcher/graph configurations.
2. **§3.2 time-travel**: spec `PolicyState`-at-T reconstruction + `evaluate_at`/`scope_at` + retroactive enumeration helper.
3. **Consumer prerequisites**: node deletion commands (UA/OA/PC) for tenant-lifecycle cleanup; dependency rev alignment with consuming workspaces.
4. **Relative matchers** (`resource.attr == subject.attr`): only when a consumer concretely needs them. They are invariant-safe — subject attributes are bound in both operations, so relative matchers compile to concrete constraints at scope time.
5. **§3.3 obligations**: after 1–3, with a named consumer use case.
6. **Server mode / bindings**: deferred until external demand exists *for the differentiators*.

## 6. Positioning Statement

> **Sentinel is the authorization engine where list queries are provably consistent with point checks, and every policy decision is auditable retroactively.**

Everything on the roadmap should make at least one of those two sentences stronger.
