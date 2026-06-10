# Sentinel Project Progress

## Current Status

### Completed Tasks

1. **Catacloud Codebase Scout** (2026-06-10)
   - Explored authorization model of target integration project
   - Identified 23-crate workspace with multi-tenant organization-based scoping
   - Mapped current auth patterns: JWT credentials with role + org_id, handler-level checks, list query filtering
   - Found 113 authorization check occurrences scattered across web handlers
   - Documented domain model: jobs, machines, files, billing, annotations resources
   - Analyzed epoch event sourcing integration (PostgreSQL backend)
   - Assessed integration feasibility: strong alignment with NGAC model, mild refactoring needed
   - Generated comprehensive scout report: `/tmp/scout-catacloud.md`

### Key Findings

**Current CataCloud Authorization**:
- Authentication: JWT tokens in Authorization header or session cookies
- Credentials structure: UUID (user_id), Role enum (PlatformAdmin | OrganizationAdmin | OrganizationMember), organization_id
- Multi-tenancy: Users belong to orgs; resources (jobs, machines, files) scoped by organization_id
- Shared pools: Explicit grants via `organization_shared_pools` table or default-access flag
- Authorization enforcement: Primarily handler-level role checks + query-level org_id filtering

**Authorization Scatter Issues**:
- 113+ role/permission checks across `/api/` handlers
- No centralized policy engine
- List query scoping manually constructed per handler
- Resource-level checks (pool access) partially centralized in helpers

**Epoch Integration**:
- 23+ aggregates (Job, JobConfiguration, Machine, Organization, User, etc.)
- Commands carry credentials but no authorization enforcement within aggregates
- PostgreSQL backend with saga pattern for long-running processes

**Sentinel Integration Recommendation**:
- Implement via middleware/extractor in `web/src/auth.rs`
- Map NGAC model: User ← Roles, UserAttribute ← Org membership, ObjectAttribute ← Resource scope
- Phase approach: policy facade → extractor integration → handler migration → optional aggregate-level enforcement

---

## Next Steps (Not Yet Started)

1. **Design NGAC Policy Model** for catacloud domain
   - Define node types for users, roles, orgs, resources
   - Map existing Role enum to NGAC User Attributes
   - Design Object Attribute node schema

2. **Implement Sentinel-CataCloud Integration Crate**
   - Create `catacloud-policy` wrapper around sentinel_core
   - Initialize policy graph from database state
   - Implement event sync (policy graph updates on IamCommand events)

3. **Middleware Integration**
   - Add policy evaluation step to `FromRequest` for Credentials
   - Compute access scopes for each request
   - Inject scope into AppState

4. **Handler Migration (Phased)**
   - Replace role checks with `evaluate()` calls
   - Use scope output to auto-filter list queries
   - Add per-resource attribute constraints

5. **Testing**
   - Unit tests for policy evaluation
   - Integration tests with existing catacloud test suite
   - Performance benchmarks (policy graph size)

---

## Architecture Notes

- **Workspace**: 23-crate multi-service architecture
- **Framework**: Actix-web for HTTP, epoch for event sourcing
- **Database**: PostgreSQL with sqlx
- **Multi-tenancy**: Organization-centric with explicit user-org membership

## References

- **Scout Report**: `/tmp/scout-catacloud.md`
- **Catacloud Repo**: `/home/istar/code/catallactical/catacloud`
- **Sentinel Repo**: `/home/istar/code/sentinel` (this project)
- **Key Files**:
  - `web/src/auth.rs` — JWT extraction
  - `web/src/api/*` — Handler authorization patterns
  - `web/src/pool_access.rs` — Resource access validation
  - `types/src/auth/mod.rs` — Credentials types
  - `iam-types/src/commands.rs` — Command definitions
  - `integration/src/lib.rs` — Aggregate setup

---

**Last Updated**: 2026-06-10  
**Status**: Reconnaissance complete; design phase ready
