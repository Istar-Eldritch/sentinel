// Brainstorm: Policy Enforcement & Authorization (NGAC-Inspired)
//
// Origin: Brainstormed in the catacloud project, moved here when sentinel
//         was established as a standalone library.
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

Catacloud needs a better security model. The current authorization system
has *194+ inline role checks* scattered across *35+ files*, with patterns
like:

```rust
if credentials.app_metadata.role != Role::PlatformAdmin {
    return Err(Unauthorized);
}
```

There are known gaps (3 `TODO: Unauthorized` comments where checks were
skipped entirely). The machine supervisor runs with `Role::PlatformAdmin`
credentials (explicit TODO to fix). The system is unsustainable to audit
and difficult to verify for security holes.

The opportunity is to build a standalone, domain-agnostic NGAC-inspired
authorization library ("sentinel") that centralizes all access control
into a Policy Enforcement Point with a real policy graph, making the
system auditable, extensible, and eventually dynamic.

#hr()

= CONTEXT & BACKGROUND

== Current Authorization State

#table(
  columns: (1fr, 2fr),
  table.header([*Aspect*], [*Current State*]),
  [Roles], [3 flat roles: `PlatformAdmin`, `OrganizationAdmin`, `OrganizationMember` --- no hierarchy],
  [Enforcement layers], [Web handlers (gate HTTP by role) AND aggregates (re-check inside commands) --- inconsistent],
  [Inline checks], [194+ occurrences of `role != Role::PlatformAdmin` across 35 files],
  [Known gaps], [3 `TODO: Unauthorized` in `job/new.rs`, `job/get_job.rs`, `job/job_confirmation.rs`],
  [Machine credentials], [Supervisors use `PlatformAdmin` role --- can do anything an admin can],
  [Read-path auth], [Ad hoc: each handler builds its own `FilterLogic` with org\_id/user\_id constraints],
  [PEP], [None --- decisions baked into business logic],
)

== Existing Proto-NGAC Patterns

The system already has NGAC-like association tables that are not
recognized as such:

- `organization_job_configurations` --- Org → can\_use → JobConfiguration
- `organization_machine_definitions` --- Org → can\_use → MachineDefinition
- `GrantJobConfigurationAccess` / `RevokeJobConfigurationAccess` commands
- `MachineDefinitionAccessGranted` / `MachineDefinitionAccessRevoked` events
- `is_default_access` flag on MachineDefinition for universal access

These are NGAC *associations between a User Attribute (Organization) and
an Object Attribute (resource type) with an access right set*. The
system already thinks in these terms --- it just doesn't call them that.

== Resource Landscape

- *User-facing aggregates* (need policy enforcement): Job, File,
  Organization, MachinePool, MachineDefinition, Invite, User,
  JobConfiguration (~8 aggregates)
- *System-only aggregates* (called only by sagas with system credentials):
  Credit, BillingLedger, Invoice, Subscription, CreditReservation,
  CreditPurchase, SubscriptionPlan, CreditPackageDefinition,
  ServiceCapacity (~9 aggregates)
- *~17 aggregates total*, roughly half need user-facing auth

== Relationship to Domain Separation

The domain separation RFC (`2602141214`) plans to split into 5 bounded
contexts. Sentinel would be a cross-cutting infrastructure layer (like
epoch) that every domain depends on. The cross-domain access grants
(`GrantJobConfigurationAccess`, `GrantMachineDefinitionAccess`) currently
on `OrganizationAggregate` would move to sentinel, resolving false
coupling between IAM and other domains.

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

*Default access* (like `is_default_access` on MachineDefinition) is an
association from a root UA ("any\_authenticated\_user") to the specific
resource's OA. Same mechanism as specific-object grants.

*Transitive file visibility* (4 paths today: own file, own job's file,
org's file, org's config's file) is modeled as 4 separate OA nodes with
4 associations, each carrying a different attribute key. Scope resolution
OR-combines them naturally. Sentinel stays generic --- the transitive
relationships are expressed as separate OAs, not as sentinel-level
concepts.

#hr()

== Design Decision 2: NGAC Graph with 5 Node Types

#table(
  columns: (auto, auto, 2fr),
  table.header([*Type*], [*NGAC Name*], [*Catacloud Equivalent*]),
  [U], [User], [Individual user (alice, bob)],
  [UA], [User Attribute], [Role-in-org: "alpha\_member", "platform\_admin"],
  [OA], [Object Attribute], [Resource scope with attribute metadata],
  [PC], [Policy Class], [Top-level scope: "org\_alpha", "platform"],
)

Two relationship types:
- *Assignments*: U→UA, UA→UA, OA→OA, OA→PC (hierarchy/containment)
- *Associations*: (UA, OA, \{access\_rights\}) --- permission grants

Example graph for Catacloud:

```
Users:                User Attributes:         Policy Classes:
  alice ─────────────► alpha_member ──────────► org_alpha
  bob ───────────────► alpha_admin ───────────► org_alpha
  admin ─────────────► platform_admin ────────► platform

Object Attributes (with attribute metadata):
  alpha_jobs:    { resource_type: "job",  key: "organization_id", values: [alpha] }
  alpha_files:   { resource_type: "file", key: "organization_id", values: [alpha] }
  specific_job:  { resource_type: "job",  key: "id",              values: [job-123] }

Associations:
  (alpha_member, alpha_jobs, {read, create})
  (alpha_admin,  alpha_jobs, {read, create, cancel_any, admin})
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
    ScopeConstraint::Attribute { key: "organization_id", values: vec![alpha_id] },
    ScopeConstraint::Attribute { key: "id", values: vec![job_123_id] },
])

// Application translates to SQL-compatible filters:
// WHERE organization_id = alpha_id OR id = job_123_id
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
#[actix_web::get("/files")]
async fn list_files(
    credentials: Credentials,
    scope: SentinelScope<FileFilter>,  // auto-resolved extractor
    ...
) -> Result<...> {
    params_filters.apply_scope(scope);
    // ... query with scoped filters
}
```

The extractor can use route parameters to automatically provide
scoped arguments. This is application-level sugar on top of sentinel's
generic scope output.

Gate macros handle ~80% of inline auth (the 194 role checks). Scope
extractors handle the list-query pattern.

#hr()

== Design Decision 6: Sentinel Before Domain Separation

Sentinel should be built and integrated *before* the domain bounded
context refactor (RFC 2602141214):

- Extracts cross-domain access grants from `OrganizationAggregate`
  into sentinel (resolves false coupling)
- Simplifies domain separation by removing cross-domain access patterns
- Each future domain crate depends on sentinel as infrastructure
- The PEP is domain-agnostic --- doesn't need to know about bounded
  contexts

#hr()

== Future: Hierarchical Administration

NGAC natively supports org-scoped policy management: the same
enforcement mechanism governs both data access AND policy modification.

```
(alpha_admin, alpha_policy_subtree, {create_association, remove_association})
```

When Alice (org admin) tries to create a policy, the PEP checks: can
Alice modify this part of the graph? Scoped to her policy class subtree.
She can create associations within `org_alpha` but not `org_beta`.

This is modelable entirely within sentinel --- the framework handles
mechanics, the application defines policy structure. Not needed for MVP
but a powerful differentiating feature for the future.

#hr()

== MVP Definition

The minimum viable sentinel that makes the system strictly better than
today:

#field-list(
  ("Graph", "Platform PC, per-org PCs, role-based UAs, per-resource-type OAs with organization_id attribute matching"),
  ("PEP", "`evaluate()` for point checks + `scope()` for list filters"),
  ("Write enforcement", "Gate macro for aggregate commands (eliminates inline auth)"),
  ("Read enforcement", "Scope extractor for web handlers (replaces ad-hoc filter building)"),
  ("Backends", "Uses epoch backends configured by the application (in-memory for tests, PG for production)"),
  ("Outcome", "Centralized, auditable enforcement --- no more scattered role checks"),
)

*NOT included in MVP*: dynamic policy UI, hierarchical administration,
specific-object grants, transitive file visibility modeled in graph
(kept in application logic initially).

#hr()

= OUT OF SCOPE

- *Integration specifics*: How catacloud seeds the graph, how sagas
  issue sentinel commands, specific filter translation code --- these
  are application-level concerns for the integration spec
- *Dynamic policy UI*: Future enhancement; architecture supports it
- *Authentication*: Sentinel handles authorization only; JWT/sessions
  stay as-is
- *Billing/capability checks*: "Can this org submit a job?" based on
  credits is a capability check, not authorization --- remains separate
- *Supervisor role details*: The machine credential fix is adjacent;
  sentinel provides the framework, but `Subject::Machine` specifics
  are an integration detail

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

5. *Transitive visibility long-term*: Files have 4 visibility paths
   modeled as 4 OA nodes. Is this sufficient long-term, or would
   sentinel ever benefit from understanding transitivity natively?

#hr()

= ROUGH SCOPE ASSESSMENT

This is an *epic-level effort*, decomposable into at least 3 specs:

#table(
  columns: (auto, 2fr, auto),
  table.header([*Phase*], [*Scope*], [*Estimate*]),
  [1], [*Sentinel library* (standalone): Core graph model (`sentinel_core`), PEP evaluation, scope resolution, derive macros (`sentinel_derive`), facade crate. Uses epoch for event sourcing --- no sentinel-specific backends. Developed and tested independently.], [2--3 weeks],
  [2], [*Catacloud integration*: Replace 194+ inline checks, migrate access grant tables into policy graph, add scope extractors, fix TODO gaps, add Machine/System subject types.], [2--3 weeks],
)

*Total estimate*: ~4--6 weeks of focused work, delivered incrementally.
The sentinel library is independently valuable and testable. Integration
can proceed aggregate-by-aggregate.

*Dependency*: Should complete before the domain bounded context
separation (RFC 2602141214) to simplify that refactor.

#hr()

= RELATED DOCUMENTS

- [Domain Bounded Context Separation](./2602141214_rfc_domain_bounded_context_separation.typ) ---
  RFC that sentinel should precede
- [Entity Relationships Guide](./015_guide_entity_relationships.md) ---
  Resource ownership model
- [Job Infrastructure](./018_spec_infra_job_infrastructure.md) ---
  Saga patterns and machine lifecycle
- [Testing Strategy](./030_guide_testing_strategy.md) ---
  Testing pyramid for sentinel integration

#note-box[
  This document captures brainstorm outcomes. Next step: create a
  formal spec (`spec_auth_sentinel_library.typ`) with detailed
  implementation plan, phase files, and success criteria.
]
