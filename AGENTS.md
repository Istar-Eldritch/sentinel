# AI Agent Collaboration Guide

This document provides guidelines for AI agents collaborating on the `sentinel` project.

## 1.0 Project Overview

Sentinel is a Rust library implementing NGAC-inspired (Next Generation Access Control) policy enforcement. It provides a centralized Policy Enforcement Point (PEP) backed by an attribute-matching policy graph, enabling applications to make authorization decisions through a single, auditable system.

Key characteristics:
- **Domain-agnostic**: Applications define their own resource types, operations, and attribute vocabularies
- **Attribute-matching**: Resources are NOT nodes in the graph; Object Attribute (OA) nodes carry metadata about which resource attributes they match, keeping the graph small regardless of data volume
- **Event-sourced**: The policy graph is persisted via the `epoch` CQRS/event-sourcing framework — sentinel uses epoch for storage, it does not implement its own backends
- **Two enforcement modes**: Point checks (`evaluate`) for command authorization and scope resolution (`scope`) for list-query filter injection

### Crate Structure

```
sentinel/
├── sentinel_core/     # Pure graph model, traits, PEP evaluation, scope resolution
├── sentinel_derive/   # Proc macros for policy enforcement annotations
└── sentinel/          # Facade crate with feature-gated re-exports
```

Sentinel depends on `epoch_core` for event sourcing. The consuming application configures epoch's backends (PG for production, in-memory for tests) — sentinel has no backend-specific crates.

## 2.0 The Agent's Role

As an AI agent, you are a collaborator in this project. Your primary responsibilities include:

- **Implementing Features**: Writing Rust code to implement new functionality as defined in specifications.
- **Writing Tests**: Creating unit and integration tests following TDD principles.
- **Bug Fixes**: Identifying and fixing bugs in the existing codebase.
- **Refactoring**: Improving structure, performance, and readability without changing external behavior.
- **Documentation**: Maintaining rustdoc comments and architecture documentation.

## 3.0 Getting Started

1. **List Files**: Start by listing project files, avoiding `target/`.
2. **Read `Cargo.toml`**: Inspect workspace and crate dependencies.
3. **Build**: `cargo build` to verify the development environment.
4. **Test**: `cargo test` to run the existing test suite.

## 4.0 Core Development Workflow

**The agent must not write any code until the developer has explicitly approved the implementation plan.**

1. **User Prompt**: The developer initiates a task.
2. **Codebase Grounding**: Explore the existing codebase, avoiding `target/`.
3. **Specification Generation**: Create or update a spec in `specs/`. Detail files to modify, code changes, new dependencies, and expected outcome.
4. **User Review**: Wait for developer approval of the spec.
5. **Implementation Plan**: Generate a step-by-step plan following TDD (failing test → implementation → refactor).
6. **User Review**: Wait for developer approval of the plan.
7. **Implementation**: Follow the approved plan precisely.
8. **Verification**: Run tests to verify changes and check for regressions.
9. **Summarize**: Provide a concise summary of implemented changes.

## 5.0 Code Style & Conventions

- **Formatting**: `cargo fmt`
- **Linting**: `cargo clippy -- -D warnings` — zero warnings
- **Error Handling**: Use proper error types. No `unwrap()`/`expect()` in library code (tests OK).
- **Documentation**: All public APIs must have rustdoc comments.
- **Dependencies**: Keep minimal and justified.

### Commit Convention

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

**Types**: `feat`, `fix`, `refactor`, `test`, `docs`, `perf`, `chore`

**Scopes**: `core`, `derive`, `graph`, `pep`, `scope`

**Examples**:
```
feat(core): implement policy graph node types and assignments
feat(pep): add evaluate() for point access checks
feat(scope): implement scope resolution with attribute constraints
test(core): add graph traversal property tests
docs(core): document PEP trait and usage patterns
```

## 6.0 Code Organization Convention

Follow a natural growth pattern where structure emerges from complexity:

1. **Start Simple**: Single `.rs` file for new functionality
2. **Grow**: Add features as the module evolves
3. **Split**: When complexity emerges (~500-1000 lines or clear conceptual divisions), create a directory
4. **Nest**: Apply the same pattern recursively for complex components
5. **Elevate**: Move shared code to the lowest common ancestor

### Key Principles

- **Avoid Premature Abstraction**: Don't create directories or split files "just in case"
- **Follow Domain Boundaries**: Group by feature/responsibility, not technical layer
- **Keep Related Code Close**: Code that changes together lives together
- **Test Structure Mirrors Source**: Split tests along the same boundaries as source

## 7.0 Architecture: NGAC-Inspired Policy Graph

### Graph Model

The graph has 4 node types:

| Type | NGAC Name | Description |
|------|-----------|-------------|
| U | User | Individual subject (user, machine, system process) |
| UA | User Attribute | Role, group, or subject category |
| OA | Object Attribute | Resource scope with attribute metadata |
| PC | Policy Class | Top-level policy scope (org, platform) |

Two relationship types:
- **Assignments**: U→UA, UA→UA, OA→OA, OA→PC (hierarchy)
- **Associations**: (UA, OA, {access_rights}) — permission grants

### Attribute-Matching Model

Object Attribute nodes carry metadata about resource attributes they match:

```rust
ObjectAttribute {
    id: Uuid,
    name: "alpha_jobs",
    resource_type: "job",
    attribute_key: "organization_id",
    attribute_values: vec![alpha_org_id],
}
```

This keeps the graph small (hundreds of nodes) regardless of data volume. Specific-object access uses the same mechanism with `attribute_key: "id"`.

### PEP (Policy Enforcement Point)

Two operations:
- **`evaluate(subject, operation, resource_attrs) → Decision`**: Point check for command authorization
- **`scope(subject, operation, resource_type) → AccessScope`**: Produces attribute constraints for list-query filter injection

### Event Sourcing

The policy graph is event-sourced using `epoch_core`. Policy mutations (create node, add assignment, create association) are commands processed by a policy aggregate that emits events. This provides a full audit trail of policy changes.

## 8.0 Testing

- **Unit Tests**: Each module should have its own tests
- **Integration Tests**: In the `tests/` directory for cross-module interaction
- **Run**: `cargo test`

### Guidelines

- **Parallel & Isolated**: Tests run in parallel; don't rely on shared mutable state
- **Idempotent**: Tests must pass on repeated runs
- **Behavior-Focused**: Test observable behavior and contracts, not implementation details
- **TDD**: Write failing test first, then implement, then refactor

## 9.0 Related Documentation

- **Brainstorm**: `docs/2602180855_brainstorm_policy_enforcement_authorization.typ` — original design brainstorm with full context on attribute-matching vs objects-in-graph, scope constraint design, and integration strategy
- **Epoch Guide**: The epoch framework's `docs/guide.md` explains event sourcing patterns sentinel builds on
