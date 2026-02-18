// Brainstorm: Policy Enforcement & Authorization (NGAC-Inspired)
//
// Compile:
//   typst compile docs/2602180855_brainstorm_policy_enforcement_authorization.typ

#import "_template.typ": *

#show: doc-setup.with(
  title: "POLICY ENFORCEMENT & AUTHORIZATION",
  subtitle: "NGAC-INSPIRED SECURITY MODEL BRAINSTORM",
  section: "2602180855",
  status: "DRAFT",
  date: "FEB 2026",
  updated: "2026-02-18",
)

= PROBLEM / OPPORTUNITY

Applications that grow organically tend to accumulate scattered inline
authorization checks. A common pattern in Rust web backends:

```rust
if credentials.role != Role::Admin {
    return Err(Unauthorized);
}
```

As a codebase matures, these checks proliferate across handlers,
aggregate commands, and business logic — with no single place to audit
or reason about the full access control policy. Known gaps and
workarounds (e.g., service accounts granted admin roles for convenience)
compound over time.

The opportunity is *sentinel*: a standalone, domain-agnostic
NGAC-inspired authorization library that centralizes all access control
into a Policy Enforcement Point backed by a real policy graph, making the
system auditable, extensible, and eventually dynamic.

#hr()

= CONTEXT & BACKGROUND

== The Typical Authorization Problem

A typical application needing policy enforcement has:

- *Flat roles* (e.g., `PlatformAdmin`, `OrgAdmin`, `Member`) with no
  hierarchy — privileges are either all-or-nothing within a role
- *Inconsistent enforcement layers* — checks at the HTTP handler level
  and duplicated inside aggregate commands
- *Ad-hoc list-query auth* — each handler manually constructs its own
  filter constraints (e.g., `WHERE organization_id = $1`)
- *No PEP* — authorization decisions are baked into business logic

== Existing Proto-NGAC Patterns

Many applications already have NGAC-like association tables that are not
recognized as such:

- Tables linking Organizations to the resource types they are allowed to
  use (e.g., `organization_job_configurations`, `organization_machine_definitions`)
- Grant/revoke commands and events for cross-resource access
- Flags like `is_default_access` for universal access

These are NGAC *associations between a User Attribute (Organization) and
an Object Attribute (resource type) with an access right set*. The
domain already thinks in these terms --- it just doesn't call them that.

== Resource Landscape

A typical multi-tenant SaaS application has:

- *User-facing aggregates* that need policy enforcement: e.g., Job,
  File, Organization, MachinePool, Invite, User, Configuration
- *System-only aggregates* called only by internal services with system
  credentials: billing, invoicing, capacity management, etc.

Sentinel focuses on user-facing aggregates where authorization decisions
are non-trivial.

#hr()

= PROPOSED DIRECTION: STANDALONE NGAC-INSPIRED LIBRARY

== Library Structure

Build a standalone, domain-agnostic library. Unlike epoch (which provides
its own backend abstractions), sentinel *uses* epoch for persistence and
event sourcing. The application configures epoch's backends (PG,
in-memory, etc.) and sentinel operates through them --- no
sentinel-specific storage crates needed.

```
sentinel/
├── sentinel_core/     # Pure graph model, traits, PEP evaluation
├── sentinel_derive/   # Proc macros (e.g., #[sentinel_policy])
└── sentinel/          # Facade crate
```

Sentinel depends on `epoch_core`. The application provides the
configured epoch backends (event store, state store) when initializing
sentinel --- the same way it configures any other epoch-based aggregate.

#hr()

== Design Decision 1: Attribute-Matching Model

Objects (Jobs, Files, etc.) are *NOT* nodes in the graph. Instead,
Object Attribute (OA) nodes carry metadata about which resource
attributes they match. The graph stays small (hundreds of nodes)
regardless of data volume.

=== Cost Analysis: Objects-in-Graph

With data doubling monthly:

#table(
  columns: (auto, auto, auto, auto, auto),
  table.header([*Month*], [*Jobs*], [*Files*], [*Object Nodes*], [*Graph Memory*]),
  [0], [1K], [5K], [6K], [~1.2 MB],
  [6], [64K], [320K], [384K], [~77 MB],
  [12], [4M], [20M], [24M], [~4.8 GB],
  [18], [256M], [1.2B], [1.5B], [~300 GB],
)

Scope resolution becomes O(objects in reachable OAs) instead of
O(graph depth). Write amplification doubles every resource creation
event.

=== Attribute-Matching Approach

With attribute-matching: scope resolution touches ~20 structural nodes
regardless of data volume, then produces SQL-friendly constraints.

*Specific-object access* is handled uniformly: an OA with
`attribute_key: "id"` and `attribute_values: [specific_object_id]`. Same
graph traversal, different attribute key. No special mechanism needed.

*Default access* (e.g., public resources visible to all authenticated
users) is an association from a root UA (`any_authenticated_user`) to the
specific resource's OA. Same mechanism as specific-object grants.

*Transitive visibility* (e.g., a user can see a file because they own the
job it belongs to) is modeled as separate OA nodes — one per visibility
path — each with a different attribute key. Scope resolution OR-combines
them naturally. Sentinel stays generic: transitive relationships are
expressed as separate OAs, not as sentinel-level concepts.

#hr()

== Design Decision 2: NGAC Graph with 4 Node Types

#table(
  columns: (auto, auto, 2fr),
  table.header([*Type*], [*NGAC Name*], [*Description*]),
  [U], [User], [Individual subject (user, machine, system process)],
  [UA], [User Attribute], [Role, group, or subject category],
  [OA], [Object Attribute], [Resource scope with attribute metadata],
  [PC], [Policy Class], [Top-level policy scope (org, platform)],
)

Two relationship types:
- *Assignments*: U→UA, UA→UA, OA→OA, OA→PC (hierarchy/containment)
- *Associations*: (UA, OA, \{access\_rights\}) --- permission grants

Example graph for a multi-tenant SaaS (ACME Corp uses sentinel):

```
Users:                User Attributes:         Policy Classes:
  alice ─────────────► acme_member ───────────► org_acme
  bob ───────────────► acme_admin ────────────► org_acme
  platform ──────────► platform_admin ────────► platform

Object Attributes (with attribute metadata):
  acme_jobs:  { resource_type: "job",  key: "organization_id", values: [acme_id] }
  acme_files: { resource_type: "file", key: "organization_id", values: [acme_id] }
  job_42:     { resource_type: "job",  key: "id",              values: [job-42-uuid] }

Associations:
  (acme_member, acme_jobs,  {read, create})
  (acme_admin,  acme_jobs,  {read, create, cancel_any, admin})
  (platform_admin, platform, {all})
```

#hr()

== Design Decision 3: Event-Sourced Graph via Epoch

The graph itself is an event-sourced aggregate with policy events:

```rust
enum PolicyEvent {
    UserAssigned { user_id: Uuid, user_attribute_id: Uuid },
    AssociationCreated { ua_id: Uuid, oa_id: Uuid, rights: AccessRightSet },
    AssociationRemoved { ua_id: Uuid, oa_id: Uuid },
    PolicyClassCreated { pc_id: Uuid, name: String },
    ObjectAttributeCreated { oa_id: Uuid, resource_type: String,
                             attribute_key: String, attribute_values: Vec<Uuid> },
    // ...
}
```

Benefits:
- Full audit trail of every policy change
- Temporal queries: "What could Alice access on January 15th?"
- Multi-instance safety: events in PG are source of truth
- Replay: rebuild graph from events after schema changes

Sentinel depends on `epoch_core`. The application provides epoch backends
(PG for production, in-memory for tests) --- sentinel has no
backend-specific crates of its own.

#hr()

== Design Decision 4: Scope System with Attribute Constraints

OA nodes carry attribute metadata. Scope resolution collects reachable
OAs and outputs generic attribute constraints:

```rust
pub enum ScopeConstraint {
    Attribute { key: String, values: Vec<Uuid> },
    Any(Vec<ScopeConstraint>),   // OR
    All(Vec<ScopeConstraint>),   // AND
}

pub enum AccessScope {
    Unrestricted,                        // e.g., platform admin
    Constrained(Vec<ScopeConstraint>),   // OR-combined constraints
    None,                                // no access
}
```

The application translates these to its own filter types:

```rust
// Sentinel outputs (generic):
AccessScope::Constrained(vec![
    ScopeConstraint::Attribute { key: "organization_id", values: vec![acme_id] },
    ScopeConstraint::Attribute { key: "id", values: vec![job_42_id] },
])

// Application translates to SQL-compatible filters:
// WHERE organization_id = acme_id OR id = job_42_id
```

=== Why Attribute Constraints Over Raw OA IDs

Two approaches were considered:

#table(
  columns: (1fr, 1fr, 1fr),
  table.header([*Aspect*], [*Graph-Native (OA IDs)*], [*Attribute Constraints*]),
  [Library output], [Raw OA node IDs], [Key-value pairs],
  [App registration], [Required per-OA mapping], [None --- self-describing],
  [Dynamic policies], [Need code deploy for new OA], [New OA works immediately],
  [Domain agnosticism], [Fully generic], [Knows about "attributes"],
  [Sync risk], [OA ↔ mapping can drift], [Single source of truth],
)

Attribute constraints were chosen because:
- Dynamic policies via UI don't require code changes
- No registration step to keep in sync
- Closer to NGAC's native model where OAs have properties

#hr()

== Design Decision 5: Two PEP Integration Points

=== Writes: Macro-Based Gate for Aggregate Commands

```rust
#[sentinel_policy]
impl Aggregate<ApplicationEvent> for JobAggregate {
    #[require(Operation::Create, ResourceType::Job)]
    async fn handle_create_job(...) { /* no inline auth */ }

    #[system_only]  // Only System subjects (sagas)
    async fn handle_mark_job_as_failed(...) { ... }
}
```

The macro generates a wrapper that:
1. Extracts credentials from the command
2. Calls `pep.evaluate(subject, operation, resource_attrs)`
3. If denied, returns `Unauthorized` error
4. If allowed, delegates to the inner function

=== Reads: Scope Extractor for Web Handlers

```rust
#[get("/jobs")]
async fn list_jobs(
    credentials: Credentials,
    scope: SentinelScope<JobFilter>,  // auto-resolved extractor
    ...
) -> Result<...> {
    params_filters.apply_scope(scope);
    // ... query with scoped filters
}
```

The extractor can use route parameters to automatically provide scoped
arguments. This is application-level sugar on top of sentinel's generic
scope output.

Gate macros eliminate scattered inline role checks. Scope extractors
replace ad-hoc filter building on list endpoints.

#hr()

== Future: Hierarchical Administration

NGAC natively supports org-scoped policy management: the same
enforcement mechanism governs both data access AND policy modification.

```
(acme_admin, acme_policy_subtree, {create_association, remove_association})
```

When Alice (org admin) tries to create a policy, the PEP checks: can
Alice modify this part of the graph? Scoped to her policy class subtree.
She can create associations within `org_acme` but not `org_beta`.

This is modelable entirely within sentinel --- the framework handles
mechanics, the application defines policy structure. Not needed for MVP
but a powerful differentiating feature for the future.

#hr()

== MVP Definition

The minimum viable sentinel that makes the system strictly better than
scattered inline checks:

#field-list(
  ("Graph", "Platform PC, per-org PCs, role-based UAs, per-resource-type OAs with organization_id attribute matching"),
  ("PEP", "`evaluate()` for point checks + `scope()` for list filters"),
  ("Write enforcement", "Gate macro for aggregate commands (eliminates inline auth)"),
  ("Read enforcement", "Scope extractor for web handlers (replaces ad-hoc filter building)"),
  ("Backends", "Uses epoch backends configured by the application (in-memory for tests, PG for production)"),
  ("Outcome", "Centralized, auditable enforcement --- no more scattered role checks"),
)

*NOT included in MVP*: dynamic policy UI, hierarchical administration,
specific-object grants, transitive visibility modeled in graph (kept in
application logic initially).

#hr()

= OUT OF SCOPE

- *Application integration specifics*: How a consuming application seeds
  the graph, how sagas issue sentinel commands, specific filter
  translation code --- these are application-level concerns
- *Dynamic policy UI*: Future enhancement; architecture supports it
- *Authentication*: Sentinel handles authorization only; JWT/sessions
  remain the application's responsibility
- *Capability checks*: "Can this org submit a job given their billing
  plan?" is a capability check, not authorization --- remains separate
- *Subject-type specifics*: `Subject::Machine` or service account details
  are integration concerns; sentinel provides the framework

#hr()

= OPEN QUESTIONS

1. *Naming*: "Sentinel" is a working name. Final name TBD.

2. *Error model*: Should sentinel return a uniform `AccessDenied`
   error, or should aggregates keep their own `Unauthorized` variants
   that wrap sentinel's decision? Uniform is easier to audit;
   per-aggregate gives more context.

3. *Eventual consistency*: In multi-instance deployment, there's a
   window where a newly-granted permission hasn't propagated. Is this
   acceptable? Should deny decisions (revocations) always check the
   source of truth (fail-closed pattern)?

4. *Scope constraint types beyond Uuid*: Current attributes are all
   Uuids. Would sentinel need to support string or boolean constraints
   (e.g., `file_extension = "pdf"`)? Affects `ScopeConstraint` type
   design.

5. *Transitive visibility long-term*: Multiple visibility paths
   modeled as multiple OA nodes. Is this sufficient long-term, or would
   sentinel ever benefit from understanding transitivity natively?

#hr()

= ROUGH SCOPE ASSESSMENT

This is an *epic-level effort*, decomposable into at least 2 phases:

#table(
  columns: (auto, 2fr, auto),
  table.header([*Phase*], [*Scope*], [*Estimate*]),
  [1], [*Sentinel library* (standalone): Core graph model (`sentinel_core`), PEP evaluation (`evaluate` + `scope`), scope resolution, derive macros (`sentinel_derive`), facade crate. Uses epoch for event sourcing --- no sentinel-specific backends. Developed and tested independently.], [2--3 weeks],
  [2], [*Application integration*: Replace scattered inline checks, migrate existing access-grant tables into the policy graph, add scope extractors, integrate `Subject::Machine` / `Subject::System` types.], [2--3 weeks],
)

*Total estimate*: ~4--6 weeks of focused work, delivered incrementally.
The sentinel library is independently valuable and testable. Integration
can proceed aggregate-by-aggregate.

#hr()

= RELATED DOCUMENTS

- `epoch` framework documentation --- event sourcing patterns sentinel
  builds on

#note-box[
  This document captures brainstorm outcomes. Next step: create a
  formal spec (`spec_sentinel_library.typ`) with detailed
  implementation plan, phase files, and success criteria.
]
