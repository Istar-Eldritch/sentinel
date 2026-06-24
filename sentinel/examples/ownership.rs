//! Per-record ownership using the `Relative` matcher.
//!
//! Users may read and delete documents they created. The policy graph stores
//! no user IDs — the `Relative` matcher binds `resource.created_by` to
//! `subject.user_id` at request time, so the graph size is O(policy rules),
//! not O(users × documents).
//!
//! Run with: `cargo run --example ownership`

use sentinel::prelude::*;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

fn main() {
    // ── Policy graph ────────────────────────────────────────────────────────

    let mut graph = PolicyGraph::new();

    // UA: any authenticated subject. The ownership check lives in the OA.
    // Note: All-matcher UAs match subjects with *no* attributes (unauthenticated
    // callers). Applications must enforce authentication before calling evaluate().
    let authenticated = UserAttribute {
        id: Uuid::new_v4(),
        name: "authenticated_users".to_string(),
        matcher: AttributeMatcher::All,
    };

    // OA: documents whose created_by overlaps with the subject's user_id.
    // No user IDs are stored in the policy graph; the constraint resolves
    // from the live request attributes at evaluation time.
    let owned_documents = ObjectAttribute {
        id: Uuid::new_v4(),
        name: "owned_documents".to_string(),
        resource_type: "document".to_string(),
        matcher: AttributeMatcher::Relative {
            resource_key: "created_by".to_string(),
            subject_key: "user_id".to_string(),
        },
    };

    graph.add_ua(authenticated.clone());
    graph.add_oa(owned_documents.clone());
    graph.add_association(Association {
        ua_id: authenticated.id,
        target: AssociationTarget::ObjectAttribute(owned_documents.id),
        operations: HashSet::from(["read".to_string(), "delete".to_string()]),
    });

    // ── Point checks (evaluate) ─────────────────────────────────────────────

    let user_a = "user-a";
    let user_b = "user-b";

    let own_doc_req = AccessRequest::new("read", "document")
        .subject_attrs(HashMap::from([(
            "user_id".to_string(),
            HashSet::from([user_a.to_string()]),
        )]))
        .resource_attrs(HashMap::from([(
            "created_by".to_string(),
            HashSet::from([user_a.to_string()]),
        )]));

    println!(
        "User A reads own document          → {:?}",
        evaluate(&graph, &own_doc_req)
    ); // Allow

    let other_doc_req = AccessRequest::new("read", "document")
        .subject_attrs(HashMap::from([(
            "user_id".to_string(),
            HashSet::from([user_b.to_string()]),
        )]))
        .resource_attrs(HashMap::from([(
            "created_by".to_string(),
            HashSet::from([user_a.to_string()]),
        )]));

    println!(
        "User B reads User A's document     → {:?}",
        evaluate(&graph, &other_doc_req)
    ); // Deny

    // ── Scope resolution (list-filter) ──────────────────────────────────────
    //
    // scope() resolves the Relative matcher against the live subject attributes
    // and returns a concrete Matching-equivalent constraint. The policy graph
    // never changes — only the filter values differ per caller.

    let user_a_scope = scope(
        &graph,
        &ScopeRequest::new("read", "document").subject_attrs(HashMap::from([(
            "user_id".to_string(),
            HashSet::from([user_a.to_string()]),
        )])),
    );
    println!("User A's document scope            → {user_a_scope:?}");
    // Constrained([Attribute { key: "created_by", values: ["user-a"] }])
    // → WHERE created_by IN ('user-a')

    let user_b_scope = scope(
        &graph,
        &ScopeRequest::new("read", "document").subject_attrs(HashMap::from([(
            "user_id".to_string(),
            HashSet::from([user_b.to_string()]),
        )])),
    );
    println!("User B's document scope            → {user_b_scope:?}");
    // Constrained([Attribute { key: "created_by", values: ["user-b"] }])
    // → WHERE created_by IN ('user-b')
}
