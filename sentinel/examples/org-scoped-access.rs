//! Org-scoped access using the `Matching` matcher.
//!
//! Employees of organisation "alpha" may read jobs that belong to "alpha".
//! Demonstrates both `evaluate()` (point check) and `scope()` (list-filter
//! constraint generation).
//!
//! Run with: `cargo run --example org-scoped-access`

use sentinel::prelude::*;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

fn main() {
    // ── Policy graph ────────────────────────────────────────────────────────

    let mut graph = PolicyGraph::new();

    // UA: subjects whose org_id is "alpha"
    let alpha_members = UserAttribute {
        id: Uuid::new_v4(),
        name: "alpha_members".to_string(),
        matcher: AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        },
    };

    // OA: job resources whose org_id is "alpha"
    let alpha_jobs = ObjectAttribute {
        id: Uuid::new_v4(),
        name: "alpha_jobs".to_string(),
        resource_type: "job".to_string(),
        matcher: AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        },
    };

    graph.add_ua(alpha_members.clone());
    graph.add_oa(alpha_jobs.clone());

    // Grant: alpha_members may read alpha_jobs
    graph.add_association(Association {
        ua_id: alpha_members.id,
        target: AssociationTarget::ObjectAttribute(alpha_jobs.id),
        operations: HashSet::from(["read".to_string()]),
    });

    // ── Point checks (evaluate) ─────────────────────────────────────────────

    let alice_req = AccessRequest::new("read", "job")
        .subject_attrs(HashMap::from([(
            "org_id".to_string(),
            HashSet::from(["alpha".to_string()]),
        )]))
        .resource_attrs(HashMap::from([(
            "org_id".to_string(),
            HashSet::from(["alpha".to_string()]),
        )]));

    println!(
        "Alice (org=alpha) reads alpha job  → {:?}",
        evaluate(&graph, &alice_req)
    ); // Allow

    let bob_req = AccessRequest::new("read", "job")
        .subject_attrs(HashMap::from([(
            "org_id".to_string(),
            HashSet::from(["beta".to_string()]),
        )]))
        .resource_attrs(HashMap::from([(
            "org_id".to_string(),
            HashSet::from(["alpha".to_string()]),
        )]));

    println!(
        "Bob   (org=beta)  reads alpha job  → {:?}",
        evaluate(&graph, &bob_req)
    ); // Deny

    // ── Scope resolution (list-filter) ──────────────────────────────────────
    //
    // scope() returns the exact attribute constraints to inject into a list
    // query, provably consistent with evaluate() for every resource.

    let alice_scope = scope(
        &graph,
        &ScopeRequest::new("read", "job").subject_attrs(HashMap::from([(
            "org_id".to_string(),
            HashSet::from(["alpha".to_string()]),
        )])),
    );
    println!("Alice's job scope              → {alice_scope:?}");
    // Constrained([Attribute { key: "org_id", values: ["alpha"] }])
    // → WHERE org_id IN ('alpha')

    let gamma_scope = scope(
        &graph,
        &ScopeRequest::new("read", "job").subject_attrs(HashMap::from([(
            "org_id".to_string(),
            HashSet::from(["gamma".to_string()]),
        )])),
    );
    println!("Gamma member's job scope       → {gamma_scope:?}");
    // None → return empty result set immediately
}
