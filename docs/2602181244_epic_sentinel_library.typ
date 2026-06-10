// Epic: Sentinel Policy Enforcement Library
//
// Compile:
//   typst compile docs/2602181244_epic_sentinel_library.typ

#import "_template.typ": *

#show: doc-setup.with(
  title: "SENTINEL POLICY ENFORCEMENT LIBRARY",
  subtitle: "EPIC — PHASE 1: STANDALONE LIBRARY",
  section: "2602181244",
  status: "DRAFT",
  date: "FEB 2026",
  updated: "2026-02-18",
  tagline: "NGAC-Inspired Authorization",
)

= GOAL STATEMENT

Deliver a standalone, domain-agnostic NGAC-inspired authorization
library for Rust that centralizes all access control into a Policy
Enforcement Point (PEP) backed by an attribute-matching policy graph.

Sentinel replaces scattered inline authorization checks
(`if role != Admin { return Err(Unauthorized) }`) with a single,
auditable policy graph that supports two enforcement modes:

- *Point checks* (`evaluate`) --- "Can this subject perform this
  operation on this resource?"
- *Scope resolution* (`scope`) --- "What resources of this type can
  this subject access?" → produces query filter constraints

The library is event-sourced via the epoch framework, independently
testable with in-memory backends, and designed so the consuming
application defines its own resource types, operations, and attribute
vocabularies.

*Phase context*: This epic is Phase 1 of a two-phase effort. Phase 2
(application integration --- out of scope) replaces scattered inline
checks in the consuming application, migrates existing access-grant
tables into the policy graph, and adds scope extractors.

#hr()

= REQUIREMENTS

*R1 --- Graph Model*: Implement a policy graph with 3 node types
(User Attribute, Object Attribute, Policy Class) using symmetric
attribute-matching on both the subject and resource sides. No User (U)
nodes --- subjects are identified by attribute matching against UA
nodes.

*R2 --- Attribute Matching*: Both UA and OA nodes carry an
`AttributeMatcher` enum with variants `All` (wildcard --- matches any
input) and `Matching { key, values }` (set membership check). The
same matching function works for both subject and resource sides.

*R3 --- Policy Class Support*: PC nodes exist as top-level scope
groupings. OA→PC assignments link object attributes to policy classes.
Associations can target either OA or PC nodes. A UA→PC association
with the required operation produces `AccessScope::Unrestricted`.

*R4 --- Associations*: Permission grants are
`(UA, target, HashSet<String>)` where target is either an OA or PC.
Operations are plain strings --- no wildcard, no sentinel-defined
enum. Fail-closed by design: every operation must be explicitly
listed.

*R5 --- PolicyView Trait*: PEP functions operate against a
`PolicyView` trait, not a concrete struct. The trait exposes the
access patterns the PEP needs: finding matching UAs, looking up
associations by UA, retrieving OAs, and finding OAs by PC. The
concrete `PolicyGraph` struct implements `PolicyView` for the MVP.
This decouples PEP evaluation from storage topology.

*R6 --- PEP Evaluate*: `evaluate(view, request) → Decision` takes
an `&impl PolicyView` and an `AccessRequest` (built via builder
pattern) containing subject attributes (`HashMap<String, String>`),
operation (`&str`), resource type (`&str`), and resource attributes
(`HashMap<String, String>`). Returns `Decision::Allow` or
`Decision::Deny`.

*R7 --- PEP Scope*: `scope(view, request) → AccessScope` takes an
`&impl PolicyView` and a `ScopeRequest` (built via builder pattern)
containing subject attributes, operation, and resource type. Returns
`AccessScope::Unrestricted`,
`AccessScope::Constrained(Vec<ScopeConstraint>)` (OR-combined),
or `AccessScope::None`.

*R8 --- Event-Sourced Aggregate*: The policy graph is persisted via
an epoch aggregate with a well-known fixed UUID. Policy mutations
(create node, add assignment, create association, etc.) are commands
that emit events. The aggregate state (`PolicyState`) wraps a
`PolicyGraph`. The `PolicyGraph` itself is epoch-free --- it has no
knowledge of aggregate state traits, versioning, or events.

*R9 --- Builder Pattern API*: `AccessRequest` and `ScopeRequest`
use builder patterns so future fields (e.g., environment attributes)
can be added without breaking changes.

*R10 --- Derive Macros*: `sentinel_derive` provides
`#[derive(ResourceAttributes)]` and `#[derive(SubjectAttributes)]`
proc macros that generate `Into<HashMap<String, String>>` conversions
and attribute key constants for compile-time safety.

*R11 --- Facade Crate*: The `sentinel` crate re-exports
`sentinel_core` and (optionally) `sentinel_derive` with feature-gated
re-exports, providing a single dependency for consuming applications.

#hr()

= SUCCESS CRITERIA

- `PolicyGraph` with UA, OA, PC nodes and `AttributeMatcher`-based
  matching is implemented and tested
- `PolicyView` trait is defined and `PolicyGraph` implements it
- `evaluate()` and `scope()` operate against `&impl PolicyView`,
  not a concrete struct
- `evaluate()` correctly handles: allow via UA→OA association, allow
  via UA→PC association, deny when no matching association, deny when
  operation not in rights set
- `scope()` correctly returns: `Unrestricted` for UA→PC associations,
  `Constrained` with OR-combined attribute constraints for UA→OA
  associations, `None` when no access
- `PolicyGraph` is epoch-free; `PolicyState` wraps it and implements
  epoch's aggregate state traits
- Policy aggregate is working: commands produce events, events
  rebuild state, state persists via state store
- `AccessRequest` and `ScopeRequest` builders compile and are
  extensible
- `#[derive(ResourceAttributes)]` generates
  `Into<HashMap<String, String>>` and attribute key constants
- `#[derive(SubjectAttributes)]` generates
  `Into<HashMap<String, String>>` and attribute key constants
- All tests pass with `cargo test`, zero clippy warnings,
  `cargo fmt` clean
- All public APIs have rustdoc comments

#hr()

= SCOPE & BOUNDARIES

== Included

- *`sentinel_core`*: Graph model, node types, `AttributeMatcher`,
  associations, OA→PC assignments, `PolicyView` trait, PEP
  (`evaluate` + `scope`), epoch aggregate (commands, events,
  `PolicyState` wrapper), error types
- *`sentinel_derive`*: `ResourceAttributes` and `SubjectAttributes`
  proc macros
- *`sentinel`*: Facade crate with feature-gated re-exports
- In-memory tests using `epoch_mem`

== Excluded

- Application integration (seeding, migration, scope extractors,
  gate macros for aggregates)
- Dynamic policy UI / admin API
- Hierarchical administration (using sentinel to govern policy
  modifications)
- UA→UA hierarchy (role inheritance edges)
- OA→OA hierarchy (resource scope nesting)
- PC→PC hierarchy
- `Any`/`All` nesting in `ScopeConstraint`
- Environmental/contextual attributes on requests
- Wildcard access rights (fail-closed by design)
- Read-optimized projections (MVP reads aggregate state directly)

#hr()

= FEATURE DECOMPOSITION

#table(
  columns: (auto, 2fr, 3fr, auto, auto),
  table.header([*\#*], [*Feature*], [*Description*], [*Priority*], [*Deps*]),
  [1], [Graph model, node types & PolicyView],
    [Core types: `UserAttribute`, `ObjectAttribute`, `PolicyClass`,
     `AttributeMatcher`, `Association`, `AssociationTarget`,
     `PolicyGraph`. `PolicyView` trait for read access. `PolicyGraph`
     implements `PolicyView`. Matching logic for both subject and
     resource sides. No epoch dependency in this feature.],
    [High], [---],
  [2], [Policy aggregate],
    [Event-sourced policy graph via epoch. `PolicyState` wraps
     `PolicyGraph` and implements epoch traits. Commands, events,
     `EventApplicator` impl. Single aggregate with fixed UUID.
     In-memory tests via `epoch_mem`.],
    [High], [1],
  [3], [PEP evaluate],
    [`evaluate(view, request) → Decision` over `&impl PolicyView`.
     `AccessRequest` builder. UA→OA and UA→PC association matching.
     Operation set membership check. `Decision::Allow` /
     `Decision::Deny`.],
    [High], [1],
  [4], [PEP scope],
    [`scope(view, request) → AccessScope` over `&impl PolicyView`.
     `ScopeRequest` builder. Returns `Unrestricted`, `Constrained`
     (OR-combined `ScopeConstraint::Attribute`), or `None`.],
    [High], [1],
  [5], [Integration tests],
    [End-to-end multi-tenant scenario: platform PC, per-org PCs,
     role-based UAs, per-resource-type OAs. Tests evaluate + scope
     across all role types. Aggregate command/event round-trip.],
    [High], [2,3,4],
  [6], [Derive macros],
    [`#[derive(ResourceAttributes)]` and
     `#[derive(SubjectAttributes)]` in `sentinel_derive`. Generates
     `Into<HashMap<String,String>>` and attribute key constants.
     Compile-fail tests via `trybuild`.],
    [Medium], [1],
  [7], [Facade crate],
    [Wire `sentinel` to re-export `sentinel_core` and
     `sentinel_derive`. Feature-gated `derive` flag. Verify
     imports through facade with doc-tests.],
    [Low], [1,6],
)

#hr()

= FEATURE DETAILS

== Feature 1: Graph Model, Node Types & PolicyView

The foundation of the library. All subsequent features depend on
these types. This feature has *no epoch dependency* --- it is pure
data structures and trait definitions.

*Node types and graph structure:*

```rust
pub enum AttributeMatcher {
    All,
    Matching { key: String, values: Vec<String> },
}

pub struct UserAttribute {
    pub id: Uuid,
    pub name: String,
    pub matcher: AttributeMatcher,
}

pub struct ObjectAttribute {
    pub id: Uuid,
    pub name: String,
    pub resource_type: String,
    pub matcher: AttributeMatcher,
}

pub struct PolicyClass {
    pub id: Uuid,
    pub name: String,
}

pub enum AssociationTarget {
    ObjectAttribute(Uuid),
    PolicyClass(Uuid),
}

pub struct Association {
    pub ua_id: Uuid,
    pub target: AssociationTarget,
    pub operations: HashSet<String>,
}
```

*PolicyView trait --- the read interface for the PEP:*

```rust
pub trait PolicyView {
    fn matching_uas(
        &self,
        subject_attrs: &HashMap<String, String>,
    ) -> Vec<&UserAttribute>;

    fn associations_for_ua(
        &self,
        ua_id: Uuid,
    ) -> Vec<&Association>;

    fn get_oa(
        &self,
        oa_id: Uuid,
    ) -> Option<&ObjectAttribute>;

    fn oas_for_pc(
        &self,
        pc_id: Uuid,
        resource_type: &str,
    ) -> Vec<&ObjectAttribute>;
}
```

`evaluate()` and `scope()` are generic over `&impl PolicyView`,
not tied to a concrete struct. This decouples the PEP from storage
topology --- the backing implementation could be a single in-memory
graph (MVP), a composite view over multiple projections, or a
pre-indexed lookup structure.

*PolicyGraph --- the concrete MVP implementation:*

`PolicyGraph` holds `HashMap<Uuid, UserAttribute>`,
`HashMap<Uuid, ObjectAttribute>`, `HashMap<Uuid, PolicyClass>`,
`Vec<Association>`, and OA→PC assignments. It implements
`PolicyView` and provides mutation methods (`add_ua`, `add_oa`,
`add_association`, etc.) for building the graph.

`PolicyGraph` is epoch-free --- no `AggregateState`, no versioning.
It is a plain data structure usable in tests without any epoch
infrastructure.

*Key behavior:*

`AttributeMatcher::matches(&self, attrs: &HashMap<String, String>)`
--- `All` always returns `true`; `Matching { key, values }` returns
`true` if `attrs.get(key)` is `Some(v)` and `values.contains(v)`.

#hr()

== Feature 2: Policy Aggregate

Event-sourced policy graph via epoch. A `PolicyState` wrapper holds
the `PolicyGraph` and implements epoch's `AggregateState` and
`EventApplicatorState` traits. The `PolicyGraph` itself is unaware
of epoch.

```rust
pub struct PolicyState {
    pub graph: PolicyGraph,
    version: u64,
}

impl AggregateState for PolicyState { ... }
impl EventApplicatorState for PolicyState { ... }
```

*Commands* (all carry the fixed aggregate UUID):

- `CreateUserAttribute { id, name, matcher }`
- `CreateObjectAttribute { id, name, resource_type, matcher }`
- `CreatePolicyClass { id, name }`
- `CreateAssociation { ua_id, target, operations }`
- `RemoveAssociation { ua_id, target }`
- `AssignOaToPc { oa_id, pc_id }`
- `UnassignOaFromPc { oa_id, pc_id }`

Events mirror commands 1:1. The `apply()` function on
`EventApplicator` delegates to `PolicyGraph`'s mutation methods,
keeping event application logic thin.

The application reads the graph for PEP evaluation via:

```rust
let state = aggregate.handle(command).await?;
let decision = evaluate(&state.graph, &request);
```

Tests use `epoch_mem` in-memory backends --- no database needed.

#hr()

== Feature 3: PEP Evaluate

The core authorization check. Operates against `&impl PolicyView`
--- works with any backing implementation.

```rust
pub fn evaluate(
    view: &impl PolicyView,
    request: &AccessRequest,
) -> Decision;
```

*`AccessRequest` builder:*

```rust
AccessRequest::new()
    .subject_attrs(&subject)
    .operation("create")
    .resource_type("job")
    .resource_attrs(&resource)
    .build()
```

The builder keeps the door open for future fields (e.g.,
`.environment_attrs(...)`) without breaking changes.

*Algorithm (flat graph, no hierarchy):*

+ `view.matching_uas(subject_attrs)` --- find matching UAs
+ For each matched UA, `view.associations_for_ua(ua_id)`
+ For UA→PC associations: if `operations.contains(operation)`,
  `view.oas_for_pc(pc_id, resource_type)` --- check if any returned
  OA's matcher matches `resource_attrs`. If so, `Allow`
+ For UA→OA associations: `view.get_oa(oa_id)` --- if
  `oa.resource_type == resource_type` AND
  `oa.matcher.matches(resource_attrs)` AND
  `operations.contains(operation)` --- `Allow`
+ If no association grants access --- `Deny`

Tests construct a `PolicyGraph` directly --- no aggregate or epoch
infrastructure needed.

#hr()

== Feature 4: PEP Scope

Scope resolution for list-query filter injection. Operates against
`&impl PolicyView` --- same decoupling as evaluate.

```rust
pub fn scope(
    view: &impl PolicyView,
    request: &ScopeRequest,
) -> AccessScope;
```

*`ScopeRequest` builder:*

```rust
ScopeRequest::new()
    .subject_attrs(&subject)
    .operation("read")
    .resource_type("job")
    .build()
```

*Return types:*

```rust
pub enum AccessScope {
    Unrestricted,
    Constrained(Vec<ScopeConstraint>),
    None,
}

pub enum ScopeConstraint {
    Attribute { key: String, values: Vec<String> },
}
```

*Algorithm:*

+ `view.matching_uas(subject_attrs)` --- find matching UAs
+ Collect associations with the requested operation
+ If any UA→PC association matches and
  `view.oas_for_pc(pc_id, resource_type)` returns results ---
  return `Unrestricted`
+ Collect `AttributeMatcher` values from matching UA→OA associations
  where `resource_type` matches
+ Merge into `Vec<ScopeConstraint::Attribute>` (OR-combined)
+ Return `Constrained(constraints)` or `None` if empty

Multiple constraints are OR-combined: the application translates to
`WHERE (key1 IN values1 OR key2 IN values2 ...)`.

Tests construct a `PolicyGraph` directly --- no aggregate or epoch
infrastructure needed.

#hr()

== Feature 5: Integration Tests

End-to-end multi-tenant scenario exercising the full stack.

*Graph setup:*

#field-list(
  ("Platform PC", "`platform`"),
  ("Org PCs", "`org_alpha`, `org_beta`"),
  ("UAs", "`platform_admins` (role=admin), `alpha_members` (org=alpha), `any_authenticated` (All)"),
  ("OAs", "`alpha_jobs` (job, org=alpha), `beta_jobs` (job, org=beta), `alpha_files` (file, org=alpha)"),
  ("OA→PC", "`alpha_jobs → org_alpha`, `beta_jobs → org_beta`, etc."),
  ("Associations", "`(platform_admins, platform, {read,create,delete})`, `(alpha_members, alpha_jobs, {read,create})`"),
)

*Test cases:*

- Platform admin evaluate any resource → `Allow`
- Platform admin scope → `Unrestricted`
- Alpha member read alpha jobs → `Allow`; read beta jobs → `Deny`
- Alpha member scope for jobs → `Constrained([Attribute { key: "organization_id", values: ["alpha-uuid"] }])`
- Unauthenticated subject → `Deny`
- Any authenticated user read public resources → `Allow`
- Cross-org access via ID-based UA (specific user IDs)
- Aggregate round-trip: issue commands, verify events, evaluate
  against resulting state

#hr()

== Feature 6: Derive Macros

Compile-time attribute safety via `sentinel_derive`.

*`#[derive(ResourceAttributes)]`:*

```rust
#[derive(ResourceAttributes)]
#[resource_type = "job"]
struct JobAttributes {
    id: Uuid,
    organization_id: Uuid,
    sensitivity: String,
}
```

*Generates:*

```rust
impl JobAttributes {
    pub const RESOURCE_TYPE: &'static str = "job";
    pub const ID: &'static str = "id";
    pub const ORGANIZATION_ID: &'static str = "organization_id";
    pub const SENSITIVITY: &'static str = "sensitivity";
}

impl From<JobAttributes> for HashMap<String, String> { ... }
```

`#[derive(SubjectAttributes)]` --- identical pattern without
`resource_type`.

Tests include compile-fail tests (using `trybuild`) for invalid
usage patterns.

#hr()

== Feature 7: Facade Crate

Wire up the `sentinel` facade crate. Already scaffolded ---
`sentinel/src/lib.rs` re-exports `sentinel_core` and conditionally
`sentinel_derive`. Verify imports work through the facade and the
prelude provides ergonomic access. Add a doc-test or integration
test.

#hr()

= TECHNICAL CONSIDERATIONS

== Architecture Notes

*Graph model simplification from NGAC*: Classic NGAC has 4 node
types (U, UA, OA, PC) with explicit assignment edges. Sentinel
simplifies to 3 node types (UA, OA, PC) by using attribute-matching
on the subject side --- subjects are never nodes in the graph,
they're identified by their attributes at request time. This means:

- No `UserCreated`/`UserAssigned` events --- users don't exist in
  the graph
- If a user's role or organization changes in the application,
  sentinel automatically picks it up on the next
  `evaluate()`/`scope()` call
- The graph is purely structural: it describes policies, not entities

*Write/read separation via PolicyView*: The architecture cleanly
separates writes (aggregate commands → events → state) from reads
(PEP queries against `&impl PolicyView`). The `PolicyGraph` struct
is the shared data structure --- it implements `PolicyView` for
reads and provides mutation methods used by the aggregate's event
applicator for writes. But the PEP only depends on the trait, so
the backing implementation can be swapped without touching
`evaluate()` or `scope()`.

This design was chosen over per-PC aggregates. Per-PC aggregates
optimize the write path (rare admin operations) at the cost of
complicating the read path (every request). Since `evaluate()` and
`scope()` must query across all PCs, per-PC aggregates would require
either loading all aggregate states per call or maintaining a merged
projection --- both add complexity for no practical gain when the
graph is hundreds of nodes. If scale demands it later, the migration
path is: keep the single aggregate for writes, add a `CompositeView`
that merges multiple per-PC projections for reads. No PEP code
changes needed.

*No generics*: Sentinel is completely non-generic. Operations are
`HashSet<String>`, attribute values are `Vec<String>`, attribute keys
are `String`. Type safety is provided at the application boundary via
`sentinel_derive` macros and `From` conversions. This keeps the epoch
integration straightforward --- `PolicyEvent` is a concrete type that
serializes cleanly.

*Fail-closed access rights*: No wildcard/`all` operation. Every
operation must be explicitly listed in an association's rights set.
Adding a new operation to the application requires conscious policy
updates. This prevents implicit grants to future unknown operations.

*Single aggregate*: The entire policy graph is one epoch aggregate
with a well-known fixed UUID. The graph is small by design (hundreds
of nodes) --- attribute-matching keeps it independent of data volume.
Policy changes are infrequent admin operations, so single-writer
concurrency is not a bottleneck.

*Builder pattern for future-proofing*: `AccessRequest` and
`ScopeRequest` use builders so environmental/contextual attributes
can be added later without breaking changes.

== Integration Points

*`epoch_core` dependency*: `sentinel_core` depends on `epoch_core`
for `Aggregate`, `EventApplicator`, `AggregateState`,
`EventApplicatorState`, `EventData`, `Event`, `Command`, and
`StateStoreBackend` traits. However, the core graph model
(`PolicyGraph`, `PolicyView`, node types, `AttributeMatcher`) is
epoch-free --- only the aggregate module uses epoch types. The
application provides configured epoch backends (PG for production,
in-memory for tests).

*`epoch_mem` for testing*: All sentinel tests use `epoch_mem`
in-memory backends. No database setup needed for library development.

*Application boundary*: The consuming application:

+ Configures epoch backends and creates the sentinel policy aggregate
+ Seeds the graph via policy commands (create nodes, associations)
+ Reads aggregate state to get `PolicyState`, accesses inner
  `PolicyGraph`
+ Calls `evaluate()` / `scope()` with `&state.graph` (which
  implements `PolicyView`) and request attributes
+ Uses `sentinel_derive` macros for compile-time attribute safety

*No sentinel-specific backends*: Sentinel does not have its own
storage crates. It uses epoch's backends, configured by the
application.

== Testing Strategy

*Unit tests*: Each module has co-located unit tests ---
`AttributeMatcher::matches()`, `PolicyGraph` mutations and
`PolicyView` implementation, `evaluate()` paths, `scope()` return
variants. PEP tests construct a `PolicyGraph` directly --- no epoch
infrastructure needed.

*Integration tests*: Feature 5 provides end-to-end multi-tenant
scenario testing the full stack (commands → events → state →
evaluate/scope).

*Aggregate tests*: Command/event round-trips via `epoch_mem` ---
create nodes, verify events, re-hydrate state, verify graph.

*Derive macro tests*: `trybuild` compile-pass and compile-fail tests
for `ResourceAttributes` and `SubjectAttributes`.

*TDD approach*: Each feature follows failing test → implementation →
refactor.

#hr()

= DESIGN DECISIONS

#table(
  columns: (auto, 2fr, 3fr),
  table.header([*\#*], [*Decision*], [*Rationale*]),
  [D1], [Single aggregate, fixed UUID],
    [Graph is small (hundreds of nodes), cross-PC queries essential,
     policy changes must be atomic],
  [D2], [`sentinel_core` depends on `epoch_core` but `PolicyGraph` is epoch-free],
    [`PolicyGraph` is a plain data structure with no epoch traits.
     `PolicyState` wraps it and adds epoch glue. This allows PEP
     tests without epoch infrastructure and keeps the door open for
     alternative storage topologies],
  [D3], [No generics --- operations are `HashSet<String>`],
    [Maximum simplicity; type safety via derive macros at boundary;
     clean epoch serialization],
  [D4], [`Vec<String>` for attribute values],
    [Future-proof for non-UUID attributes; sentinel doesn't interpret
     values, just passes them through],
  [D5], [No U nodes --- subject attribute-matching],
    [Symmetric design (both sides match identically); no user
     lifecycle in graph; dynamic (role changes auto-apply)],
  [D6], [3 node types: UA, OA, PC],
    [Minimal set that delivers both evaluate and scope. PC needed for
     `Unrestricted` pattern],
  [D7], [`AttributeMatcher` enum (`All` / `Matching`)],
    [No impossible states; shared by UA and OA; extensible with new
     variants],
  [D8], [Builder pattern for requests],
    [Future-proof for environment attributes without breaking
     changes],
  [D9], [Flat graph --- no UA→UA, OA→OA hierarchy],
    [Deferred; attribute overlap handles most hierarchy cases;
     additive to add later],
  [D10], [OA→PC assignments included],
    [Needed so UA→PC associations know which OAs are "under" a PC
     for scope resolution],
  [D11], [`Decision::Allow` / `Decision::Deny`],
    [Sentinel can't provide meaningful denial reasons; application
     wraps in own error type],
  [D12], [`ScopeConstraint::Attribute` flat OR],
    [Catacloud's most complex case (file visibility with 4 paths)
     maps cleanly to flat OR; nesting deferred],
  [D13], [`PolicyView` trait decouples PEP from storage],
    [PEP operates against `&impl PolicyView`, not a concrete struct.
     `PolicyGraph` implements it for the MVP. Future: composite views
     over per-PC projections, pre-indexed lookups, etc. --- no PEP
     changes needed],
  [D14], [`sentinel_derive` as late-stage feature],
    [Depends on stable core types; provides compile-time attribute
     safety],
  [D15], [No wildcard access rights],
    [Fail-closed: new operations require explicit grants; prevents
     implicit security holes],
  [D18], [Request attributes are multi-valued sets (`HashMap<String, HashSet<String>>`)],
    [Both subject and resource attributes are multi-valued: each key maps
     to a `HashSet<String>`. Matching semantics become non-empty
     intersection: `Matching { key, values }` matches when the input set
     for `key` shares at least one value with the matcher's `values`. A
     key mapped to an empty set behaves like an absent key (fail-closed).
     The policy side (`Matching::values`) stays `Vec<String>` for
     serialisation stability. Amended from the original single-valued
     design during the 2026-06-10 review.],
)

#hr()

= DEFERRED TO FUTURE

- *`Any`/`All` nesting in `ScopeConstraint`* --- for compound
  matching on multiple attribute keys
- *UA→UA / OA→OA hierarchy* --- role inheritance and resource scope
  nesting
- *PC→PC hierarchy* --- nested policy classes
- *Environmental/contextual attributes* --- timestamp, IP, location
  on requests (builder keeps door open)
- *Hierarchical administration* --- using sentinel to govern who can
  modify which parts of the policy graph
- *Dynamic policy UI* --- admin interface for policy management
- *Compound `AttributeMatcher`* --- matching on multiple keys
  simultaneously
- *Alternative `PolicyView` implementations* --- composite views
  over per-PC projections, pre-indexed lookups, database-backed
  views

#hr()

= RELATED DOCUMENTS

- *Brainstorm*: `docs/2602180855_brainstorm_policy_enforcement_authorization.typ`
  --- original design brainstorm with full context on
  attribute-matching vs objects-in-graph, scope constraint design,
  and integration strategy
- *Domain Separation RFC*:
  `~/code/catacloud/docs/2602141214_rfc_domain_bounded_context_separation.typ`
  --- catacloud domain separation (informs the no-generics decision)
- *Epoch Guide*: The epoch framework's `docs/guide.md` explains
  event sourcing patterns sentinel builds on
