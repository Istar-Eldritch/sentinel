# Sentinel

NGAC-inspired policy enforcement library for Rust.

Sentinel provides a centralized Policy Enforcement Point (PEP) backed by an attribute-matching policy graph. It is domain-agnostic — applications define their own resource types, operations, and attribute vocabularies.

## Key Concepts

- **Attribute-matching model**: Resources are not nodes in the graph. Object Attribute (OA) nodes carry metadata about which resource attributes they match, keeping the graph small regardless of data volume.
- **NGAC graph**: 4 node types (User, User Attribute, Object Attribute, Policy Class) with assignment edges and association edges carrying access rights.
- **Two enforcement modes**: Point checks (`evaluate`) for command authorization; scope resolution (`scope`) for producing query filter constraints.
- **Event-sourced**: The policy graph is persisted via the [epoch](https://github.com/mariozechner/epoch) CQRS/event-sourcing framework.

## Crate Structure

| Crate | Description |
|-------|-------------|
| `sentinel_core` | Pure graph model, traits, PEP evaluation, scope resolution |
| `sentinel_derive` | Proc macros for policy enforcement annotations |
| `sentinel` | Facade crate with feature-gated re-exports |

## Status

Early development. See `docs/` for design documents and `specs/` for implementation specifications.
