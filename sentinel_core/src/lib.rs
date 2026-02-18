//! # Sentinel Core
//!
//! Core graph model, traits, and policy evaluation for the sentinel
//! authorization library. Implements an NGAC-inspired attribute-matching
//! policy graph with a Policy Enforcement Point (PEP).

#![deny(missing_docs)]

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Determines how an attribute node matches against a set of resource or
/// subject attributes.
///
/// Used by [`UserAttribute`] and [`ObjectAttribute`] to define which
/// subjects or resources fall under their scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AttributeMatcher {
    /// Wildcard matcher — matches any attribute set unconditionally.
    All,
    /// Matches when the attribute map contains the specified `key` and
    /// its value is found in `values`.
    Matching {
        /// The attribute key to look up in the input map.
        key: String,
        /// The set of acceptable values. A match occurs when the input
        /// map's value for `key` is contained in this list.
        values: Vec<String>,
    },
}

impl AttributeMatcher {
    /// Tests whether the given attribute map satisfies this matcher.
    ///
    /// - [`AttributeMatcher::All`] always returns `true`.
    /// - [`AttributeMatcher::Matching`] returns `true` if `attrs` contains
    ///   the specified `key` and its value is in `values`; `false` otherwise.
    pub fn matches(&self, attrs: &HashMap<String, String>) -> bool {
        match self {
            AttributeMatcher::All => true,
            AttributeMatcher::Matching { key, values } => {
                attrs.get(key).is_some_and(|v| values.contains(v))
            }
        }
    }
}

/// A user attribute node representing a role, group, or subject category.
///
/// The [`matcher`](UserAttribute::matcher) determines which subjects fall
/// under this user attribute based on their attribute map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAttribute {
    /// Unique identifier for this user attribute.
    pub id: Uuid,
    /// Human-readable name (e.g., `"admins"`, `"org_alpha_members"`).
    pub name: String,
    /// Determines which subjects match this user attribute.
    pub matcher: AttributeMatcher,
}

/// An object attribute node representing a resource scope.
///
/// The [`resource_type`](ObjectAttribute::resource_type) identifies which kind
/// of resource this OA applies to, and the
/// [`matcher`](ObjectAttribute::matcher) determines which specific resources
/// within that type fall under its scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAttribute {
    /// Unique identifier for this object attribute.
    pub id: Uuid,
    /// Human-readable name (e.g., `"alpha_jobs"`, `"all_documents"`).
    pub name: String,
    /// The kind of resource this object attribute applies to (e.g., `"job"`,
    /// `"document"`).
    pub resource_type: String,
    /// Determines which resources of [`resource_type`](ObjectAttribute::resource_type)
    /// match this object attribute.
    pub matcher: AttributeMatcher,
}

/// A policy class node representing a top-level policy scope.
///
/// Policy classes group object attributes into distinct policy domains
/// (e.g., per-organization or per-platform policies).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyClass {
    /// Unique identifier for this policy class.
    pub id: Uuid,
    /// Human-readable name (e.g., `"platform_policy"`, `"org_alpha_policy"`).
    pub name: String,
}

/// The target of an association — either an object attribute or a policy class.
///
/// Used in [`Association`] to specify what the permission grant applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssociationTarget {
    /// The association targets a specific object attribute.
    ObjectAttribute(Uuid),
    /// The association targets a policy class (granting access to all OAs
    /// assigned to that policy class).
    PolicyClass(Uuid),
}

/// A permission grant linking a user attribute to a target with a set of
/// allowed operations.
///
/// Associations are the edges in the NGAC graph that carry access rights.
/// They connect a [`UserAttribute`] (identified by `ua_id`) to either an
/// [`ObjectAttribute`] or [`PolicyClass`] (via [`AssociationTarget`]), with
/// a set of operation strings defining what actions are permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Association {
    /// The user attribute this association originates from.
    pub ua_id: Uuid,
    /// The target of this permission grant.
    pub target: AssociationTarget,
    /// The set of operations permitted by this association (e.g.,
    /// `{"read", "write"}`).
    pub operations: HashSet<String>,
}

// --- PolicyView trait and PolicyGraph struct (Phase 3) ---

/// Read-only view into the policy graph for authorization queries.
///
/// This trait abstracts the read-access interface used by PEP functions
/// ([`evaluate`] and [`scope`]) so they can be written generically over
/// any policy graph implementation. The primary concrete implementation is
/// [`PolicyGraph`].
pub trait PolicyView {
    /// Returns all user attributes whose matcher matches the given subject attributes.
    ///
    /// Iterates over every [`UserAttribute`] in the graph and returns those
    /// where `matcher.matches(subject_attrs)` is `true`.
    fn matching_uas(&self, subject_attrs: &HashMap<String, String>) -> Vec<&UserAttribute>;

    /// Returns all associations originating from the given user attribute.
    ///
    /// Looks up associations by `ua_id` and returns references to all
    /// matching [`Association`] entries.
    fn associations_for_ua(&self, ua_id: Uuid) -> Vec<&Association>;

    /// Looks up an object attribute by its unique identifier.
    ///
    /// Returns `Some` if an [`ObjectAttribute`] with the given `oa_id`
    /// exists in the graph, or `None` otherwise.
    fn get_oa(&self, oa_id: Uuid) -> Option<&ObjectAttribute>;

    /// Returns all object attributes assigned to the given policy class
    /// that have the specified resource type.
    ///
    /// Filters by both the OA→PC assignment and the
    /// [`ObjectAttribute::resource_type`] field.
    fn oas_for_pc(&self, pc_id: Uuid, resource_type: &str) -> Vec<&ObjectAttribute>;
}

/// Concrete in-memory policy graph.
///
/// Stores all policy nodes ([`UserAttribute`], [`ObjectAttribute`],
/// [`PolicyClass`]), associations ([`Association`]), and OA→PC assignments.
/// Implements [`PolicyView`] for read access and provides mutation methods
/// for the event-sourcing aggregate applicator.
///
/// Use [`PolicyGraph::new()`] to create an empty graph, then populate it
/// via the mutation methods (`add_ua`, `add_oa`, `add_pc`,
/// `add_association`, `assign_oa_to_pc`, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGraph {
    /// User attribute nodes indexed by ID.
    pub(crate) user_attributes: HashMap<Uuid, UserAttribute>,
    /// Object attribute nodes indexed by ID.
    pub(crate) object_attributes: HashMap<Uuid, ObjectAttribute>,
    /// Policy class nodes indexed by ID.
    pub(crate) policy_classes: HashMap<Uuid, PolicyClass>,
    /// All associations in the graph.
    pub(crate) associations: Vec<Association>,
    /// OA→PC assignment edges stored as `(oa_id, pc_id)` pairs.
    pub(crate) oa_pc_assignments: HashSet<(Uuid, Uuid)>,
}

impl PolicyGraph {
    /// Creates a new, empty policy graph.
    ///
    /// The returned graph contains no nodes, associations, or assignments.
    pub fn new() -> Self {
        Self {
            user_attributes: HashMap::new(),
            object_attributes: HashMap::new(),
            policy_classes: HashMap::new(),
            associations: Vec::new(),
            oa_pc_assignments: HashSet::new(),
        }
    }

    /// Inserts a user attribute into the graph.
    ///
    /// If a [`UserAttribute`] with the same `id` already exists, it is
    /// overwritten (HashMap insert-or-replace semantics).
    pub fn add_ua(&mut self, ua: UserAttribute) {
        self.user_attributes.insert(ua.id, ua);
    }

    /// Inserts an object attribute into the graph.
    ///
    /// If an [`ObjectAttribute`] with the same `id` already exists, it is
    /// overwritten (HashMap insert-or-replace semantics).
    pub fn add_oa(&mut self, oa: ObjectAttribute) {
        self.object_attributes.insert(oa.id, oa);
    }

    /// Inserts a policy class into the graph.
    ///
    /// If a [`PolicyClass`] with the same `id` already exists, it is
    /// overwritten (HashMap insert-or-replace semantics).
    pub fn add_pc(&mut self, pc: PolicyClass) {
        self.policy_classes.insert(pc.id, pc);
    }

    /// Appends an association to the graph.
    ///
    /// The association is added unconditionally — no duplicate checking
    /// is performed. Validation (e.g., ensuring the UA and target exist)
    /// is the responsibility of the aggregate command handler.
    pub fn add_association(&mut self, assoc: Association) {
        self.associations.push(assoc);
    }

    /// Removes all associations matching the given `ua_id` and `target`.
    ///
    /// Because [`add_association`] appends without dedup, there may be
    /// multiple matching entries (e.g., from duplicate commands); all are
    /// removed. If no matching association exists, this is a no-op.
    pub fn remove_association(&mut self, ua_id: Uuid, target: &AssociationTarget) {
        self.associations
            .retain(|a| !(a.ua_id == ua_id && a.target == *target));
    }

    /// Adds an OA→PC assignment edge.
    ///
    /// If the assignment already exists, this is a no-op (HashSet
    /// insert semantics).
    pub fn assign_oa_to_pc(&mut self, oa_id: Uuid, pc_id: Uuid) {
        self.oa_pc_assignments.insert((oa_id, pc_id));
    }

    /// Removes an OA→PC assignment edge.
    ///
    /// If the assignment does not exist, this is a no-op (HashSet
    /// remove semantics).
    pub fn unassign_oa_from_pc(&mut self, oa_id: Uuid, pc_id: Uuid) {
        self.oa_pc_assignments.remove(&(oa_id, pc_id));
    }
}

impl Default for PolicyGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyView for PolicyGraph {
    fn matching_uas(&self, subject_attrs: &HashMap<String, String>) -> Vec<&UserAttribute> {
        self.user_attributes
            .values()
            .filter(|ua| ua.matcher.matches(subject_attrs))
            .collect()
    }

    fn associations_for_ua(&self, ua_id: Uuid) -> Vec<&Association> {
        self.associations
            .iter()
            .filter(|a| a.ua_id == ua_id)
            .collect()
    }

    fn get_oa(&self, oa_id: Uuid) -> Option<&ObjectAttribute> {
        self.object_attributes.get(&oa_id)
    }

    fn oas_for_pc(&self, pc_id: Uuid, resource_type: &str) -> Vec<&ObjectAttribute> {
        self.oa_pc_assignments
            .iter()
            .filter(|(_, pc)| *pc == pc_id)
            .filter_map(|(oa_id, _)| self.object_attributes.get(oa_id))
            .filter(|oa| oa.resource_type == resource_type)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use uuid::Uuid;

    // --- AttributeMatcher::All tests ---

    #[test]
    fn all_matcher_matches_empty_attrs() {
        let matcher = AttributeMatcher::All;
        assert!(matcher.matches(&HashMap::new()));
    }

    #[test]
    fn all_matcher_matches_any_attrs() {
        let matcher = AttributeMatcher::All;
        let attrs = HashMap::from([("key".to_string(), "value".to_string())]);
        assert!(matcher.matches(&attrs));
    }

    // --- AttributeMatcher::Matching tests ---

    #[test]
    fn matching_matcher_matches_when_key_and_value_present() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        let attrs = HashMap::from([("org_id".to_string(), "alpha".to_string())]);
        assert!(matcher.matches(&attrs));
    }

    #[test]
    fn matching_matcher_no_match_when_key_missing() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        let attrs = HashMap::from([("other".to_string(), "alpha".to_string())]);
        assert!(!matcher.matches(&attrs));
    }

    #[test]
    fn matching_matcher_no_match_when_value_differs() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        let attrs = HashMap::from([("org_id".to_string(), "beta".to_string())]);
        assert!(!matcher.matches(&attrs));
    }

    #[test]
    fn matching_matcher_matches_any_of_multiple_values() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string(), "beta".to_string()],
        };
        let attrs = HashMap::from([("org_id".to_string(), "beta".to_string())]);
        assert!(matcher.matches(&attrs));
    }

    #[test]
    fn matching_matcher_no_match_on_empty_attrs() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        assert!(!matcher.matches(&HashMap::new()));
    }

    #[test]
    fn matching_matcher_no_match_with_empty_values() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec![],
        };
        let attrs = HashMap::from([("org_id".to_string(), "alpha".to_string())]);
        assert!(!matcher.matches(&attrs));
    }

    // --- PartialEq tests ---

    #[test]
    fn all_matchers_are_equal() {
        assert_eq!(AttributeMatcher::All, AttributeMatcher::All);
    }

    #[test]
    fn matching_matchers_equal_with_same_fields() {
        let m1 = AttributeMatcher::Matching {
            key: "k".to_string(),
            values: vec!["v".to_string()],
        };
        let m2 = AttributeMatcher::Matching {
            key: "k".to_string(),
            values: vec!["v".to_string()],
        };
        assert_eq!(m1, m2);
    }

    #[test]
    fn different_matchers_not_equal() {
        let all = AttributeMatcher::All;
        let matching = AttributeMatcher::Matching {
            key: "k".to_string(),
            values: vec!["v".to_string()],
        };
        assert_ne!(all, matching);
    }

    #[test]
    fn matching_matchers_not_equal_with_different_keys() {
        let m1 = AttributeMatcher::Matching {
            key: "k1".to_string(),
            values: vec!["v".to_string()],
        };
        let m2 = AttributeMatcher::Matching {
            key: "k2".to_string(),
            values: vec!["v".to_string()],
        };
        assert_ne!(m1, m2);
    }

    // =========================================================
    // Node type tests
    // =========================================================

    // --- UserAttribute tests ---

    #[test]
    fn user_attribute_construction_with_all_matcher() {
        let id = Uuid::new_v4();
        let ua = UserAttribute {
            id,
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        assert_eq!(ua.id, id);
        assert_eq!(ua.name, "admins");
        assert_eq!(ua.matcher, AttributeMatcher::All);
    }

    #[test]
    fn user_attribute_construction_with_matching_matcher() {
        let id = Uuid::new_v4();
        let ua = UserAttribute {
            id,
            name: "org_alpha_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        assert_eq!(ua.id, id);
        assert_eq!(ua.name, "org_alpha_members");
        assert_eq!(
            ua.matcher,
            AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            }
        );
    }

    #[test]
    fn user_attribute_clone() {
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let cloned = ua.clone();
        assert_eq!(cloned.id, ua.id);
        assert_eq!(cloned.name, ua.name);
    }

    #[test]
    fn user_attribute_debug() {
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let debug_str = format!("{:?}", ua);
        assert!(debug_str.contains("UserAttribute"));
        assert!(debug_str.contains("admins"));
    }

    #[test]
    fn user_attribute_serde_roundtrip() {
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "role".to_string(),
                values: vec!["admin".to_string()],
            },
        };
        let json = serde_json::to_string(&ua).unwrap();
        let deserialized: UserAttribute = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, ua.id);
        assert_eq!(deserialized.name, ua.name);
        assert_eq!(deserialized.matcher, ua.matcher);
    }

    // --- ObjectAttribute tests ---

    #[test]
    fn object_attribute_construction() {
        let id = Uuid::new_v4();
        let oa = ObjectAttribute {
            id,
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "organization_id".to_string(),
                values: vec!["alpha-id".to_string()],
            },
        };
        assert_eq!(oa.id, id);
        assert_eq!(oa.name, "alpha_jobs");
        assert_eq!(oa.resource_type, "job");
        assert_eq!(
            oa.matcher,
            AttributeMatcher::Matching {
                key: "organization_id".to_string(),
                values: vec!["alpha-id".to_string()],
            }
        );
    }

    #[test]
    fn object_attribute_with_all_matcher() {
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "all_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        assert_eq!(oa.resource_type, "job");
        assert_eq!(oa.matcher, AttributeMatcher::All);
    }

    #[test]
    fn object_attribute_clone() {
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let cloned = oa.clone();
        assert_eq!(cloned.id, oa.id);
        assert_eq!(cloned.name, oa.name);
        assert_eq!(cloned.resource_type, oa.resource_type);
    }

    #[test]
    fn object_attribute_debug() {
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let debug_str = format!("{:?}", oa);
        assert!(debug_str.contains("ObjectAttribute"));
        assert!(debug_str.contains("alpha_jobs"));
        assert!(debug_str.contains("job"));
    }

    #[test]
    fn object_attribute_serde_roundtrip() {
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let json = serde_json::to_string(&oa).unwrap();
        let deserialized: ObjectAttribute = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, oa.id);
        assert_eq!(deserialized.name, oa.name);
        assert_eq!(deserialized.resource_type, oa.resource_type);
        assert_eq!(deserialized.matcher, oa.matcher);
    }

    // --- PolicyClass tests ---

    #[test]
    fn policy_class_construction() {
        let id = Uuid::new_v4();
        let pc = PolicyClass {
            id,
            name: "platform_policy".to_string(),
        };
        assert_eq!(pc.id, id);
        assert_eq!(pc.name, "platform_policy");
    }

    #[test]
    fn policy_class_clone() {
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_policy".to_string(),
        };
        let cloned = pc.clone();
        assert_eq!(cloned.id, pc.id);
        assert_eq!(cloned.name, pc.name);
    }

    #[test]
    fn policy_class_debug() {
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        let debug_str = format!("{:?}", pc);
        assert!(debug_str.contains("PolicyClass"));
        assert!(debug_str.contains("platform_policy"));
    }

    #[test]
    fn policy_class_serde_roundtrip() {
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        let json = serde_json::to_string(&pc).unwrap();
        let deserialized: PolicyClass = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, pc.id);
        assert_eq!(deserialized.name, pc.name);
    }

    // --- AssociationTarget tests ---

    #[test]
    fn association_target_object_attribute_variant() {
        let oa_id = Uuid::new_v4();
        let target = AssociationTarget::ObjectAttribute(oa_id);
        assert_eq!(target, AssociationTarget::ObjectAttribute(oa_id));
    }

    #[test]
    fn association_target_policy_class_variant() {
        let pc_id = Uuid::new_v4();
        let target = AssociationTarget::PolicyClass(pc_id);
        assert_eq!(target, AssociationTarget::PolicyClass(pc_id));
    }

    #[test]
    fn association_target_equality() {
        let id = Uuid::new_v4();
        let t1 = AssociationTarget::ObjectAttribute(id);
        let t2 = AssociationTarget::ObjectAttribute(id);
        let t3 = AssociationTarget::PolicyClass(id);
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn association_target_clone() {
        let target = AssociationTarget::ObjectAttribute(Uuid::new_v4());
        let cloned = target.clone();
        assert_eq!(target, cloned);
    }

    #[test]
    fn association_target_debug() {
        let target = AssociationTarget::PolicyClass(Uuid::new_v4());
        let debug_str = format!("{:?}", target);
        assert!(debug_str.contains("PolicyClass"));
    }

    #[test]
    fn association_target_serde_roundtrip_oa() {
        let target = AssociationTarget::ObjectAttribute(Uuid::new_v4());
        let json = serde_json::to_string(&target).unwrap();
        let deserialized: AssociationTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deserialized);
    }

    #[test]
    fn association_target_serde_roundtrip_pc() {
        let target = AssociationTarget::PolicyClass(Uuid::new_v4());
        let json = serde_json::to_string(&target).unwrap();
        let deserialized: AssociationTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deserialized);
    }

    // --- Association tests ---

    #[test]
    fn association_construction() {
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let ops: HashSet<String> = HashSet::from(["read".to_string(), "write".to_string()]);
        let assoc = Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: ops.clone(),
        };
        assert_eq!(assoc.ua_id, ua_id);
        assert_eq!(assoc.target, AssociationTarget::ObjectAttribute(oa_id));
        assert_eq!(assoc.operations, ops);
    }

    #[test]
    fn association_with_policy_class_target() {
        let ua_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let ops: HashSet<String> = HashSet::from(["admin".to_string()]);
        let assoc = Association {
            ua_id,
            target: AssociationTarget::PolicyClass(pc_id),
            operations: ops.clone(),
        };
        assert_eq!(assoc.target, AssociationTarget::PolicyClass(pc_id));
        assert_eq!(assoc.operations, ops);
    }

    #[test]
    fn association_with_empty_operations() {
        let assoc = Association {
            ua_id: Uuid::new_v4(),
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::new(),
        };
        assert!(assoc.operations.is_empty());
    }

    #[test]
    fn association_clone() {
        let assoc = Association {
            ua_id: Uuid::new_v4(),
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::from(["read".to_string()]),
        };
        let cloned = assoc.clone();
        assert_eq!(cloned.ua_id, assoc.ua_id);
        assert_eq!(cloned.target, assoc.target);
        assert_eq!(cloned.operations, assoc.operations);
    }

    #[test]
    fn association_debug() {
        let assoc = Association {
            ua_id: Uuid::new_v4(),
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::from(["read".to_string()]),
        };
        let debug_str = format!("{:?}", assoc);
        assert!(debug_str.contains("Association"));
        assert!(debug_str.contains("read"));
    }

    #[test]
    fn association_serde_roundtrip() {
        let assoc = Association {
            ua_id: Uuid::new_v4(),
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::from(["read".to_string(), "write".to_string()]),
        };
        let json = serde_json::to_string(&assoc).unwrap();
        let deserialized: Association = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ua_id, assoc.ua_id);
        assert_eq!(deserialized.target, assoc.target);
        assert_eq!(deserialized.operations, assoc.operations);
    }

    // =========================================================
    // PolicyView trait and PolicyGraph struct tests (Phase 3)
    // =========================================================

    // --- PolicyGraph::new() tests ---

    #[test]
    fn policy_graph_new_creates_empty_graph() {
        let graph = PolicyGraph::new();
        let subject_attrs = HashMap::new();
        let matching = graph.matching_uas(&subject_attrs);
        assert!(matching.is_empty());
    }

    #[test]
    fn policy_graph_new_has_no_associations() {
        let graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let assocs = graph.associations_for_ua(ua_id);
        assert!(assocs.is_empty());
    }

    #[test]
    fn policy_graph_new_get_oa_returns_none() {
        let graph = PolicyGraph::new();
        assert!(graph.get_oa(Uuid::new_v4()).is_none());
    }

    #[test]
    fn policy_graph_new_oas_for_pc_returns_empty() {
        let graph = PolicyGraph::new();
        let pc_id = Uuid::new_v4();
        let oas = graph.oas_for_pc(pc_id, "job");
        assert!(oas.is_empty());
    }

    // --- PolicyGraph derive tests ---

    #[test]
    fn policy_graph_debug() {
        let graph = PolicyGraph::new();
        let debug_str = format!("{:?}", graph);
        assert!(debug_str.contains("PolicyGraph"));
    }

    #[test]
    fn policy_graph_clone() {
        let graph = PolicyGraph::new();
        let cloned = graph.clone();
        assert!(cloned.matching_uas(&HashMap::new()).is_empty());
    }

    #[test]
    fn policy_graph_default() {
        let graph = PolicyGraph::default();
        assert!(graph.matching_uas(&HashMap::new()).is_empty());
    }

    #[test]
    fn policy_graph_serde_roundtrip_empty() {
        let graph = PolicyGraph::new();
        let json = serde_json::to_string(&graph).unwrap();
        let deserialized: PolicyGraph = serde_json::from_str(&json).unwrap();
        assert!(deserialized.matching_uas(&HashMap::new()).is_empty());
    }

    // =========================================================
    // PolicyGraph mutation method tests (Phase 4)
    // =========================================================

    // --- add_ua tests ---

    #[test]
    fn add_ua_inserts_user_attribute() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        let attrs = HashMap::new();
        let matching = graph.matching_uas(&attrs);
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].id, ua.id);
        assert_eq!(matching[0].name, "admins");
    }

    #[test]
    fn add_ua_overwrites_existing_with_same_id() {
        let mut graph = PolicyGraph::new();
        let id = Uuid::new_v4();
        let ua1 = UserAttribute {
            id,
            name: "original".to_string(),
            matcher: AttributeMatcher::All,
        };
        let ua2 = UserAttribute {
            id,
            name: "updated".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua1);
        graph.add_ua(ua2);
        let matching = graph.matching_uas(&HashMap::new());
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].name, "updated");
    }

    // --- add_oa tests ---

    #[test]
    fn add_oa_inserts_object_attribute() {
        let mut graph = PolicyGraph::new();
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_oa(oa.clone());
        let found = graph.get_oa(oa.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "alpha_jobs");
    }

    #[test]
    fn add_oa_overwrites_existing_with_same_id() {
        let mut graph = PolicyGraph::new();
        let id = Uuid::new_v4();
        let oa1 = ObjectAttribute {
            id,
            name: "original".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa2 = ObjectAttribute {
            id,
            name: "updated".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_oa(oa1);
        graph.add_oa(oa2);
        let found = graph.get_oa(id).unwrap();
        assert_eq!(found.name, "updated");
    }

    // --- add_pc tests ---

    #[test]
    fn add_pc_inserts_policy_class() {
        let mut graph = PolicyGraph::new();
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "all_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_pc(pc.clone());
        graph.add_oa(oa.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        let oas = graph.oas_for_pc(pc.id, "job");
        assert_eq!(oas.len(), 1);
        assert_eq!(oas[0].id, oa.id);
    }

    #[test]
    fn add_pc_overwrites_existing_with_same_id() {
        let mut graph = PolicyGraph::new();
        let id = Uuid::new_v4();
        let pc1 = PolicyClass {
            id,
            name: "original".to_string(),
        };
        let pc2 = PolicyClass {
            id,
            name: "updated".to_string(),
        };
        graph.add_pc(pc1);
        graph.add_pc(pc2);
        // `PolicyView` does not expose a direct PC lookup method, so we verify
        // via the `pub(crate)` internal field (accessible within the same crate).
        assert_eq!(graph.policy_classes.len(), 1);
        assert_eq!(graph.policy_classes.get(&id).unwrap().name, "updated");
    }

    // --- add_association tests ---

    #[test]
    fn add_association_appends_association() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let assoc = Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        };
        graph.add_association(assoc);
        let found = graph.associations_for_ua(ua_id);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target, AssociationTarget::ObjectAttribute(oa_id));
        assert!(found[0].operations.contains("read"));
    }

    #[test]
    fn add_association_allows_multiple_for_same_ua() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id1 = Uuid::new_v4();
        let oa_id2 = Uuid::new_v4();
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id1),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id2),
            operations: HashSet::from(["write".to_string()]),
        });
        let found = graph.associations_for_ua(ua_id);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn add_association_with_policy_class_target() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        let assoc = Association {
            ua_id,
            target: AssociationTarget::PolicyClass(pc_id),
            operations: HashSet::from(["admin".to_string()]),
        };
        graph.add_association(assoc);
        let found = graph.associations_for_ua(ua_id);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target, AssociationTarget::PolicyClass(pc_id));
    }

    /// `add_association` uses `push()` with no dedup. Adding the exact same
    /// association twice creates two entries. `remove_association` uses
    /// `retain()` which removes *all* matching entries — so both are cleaned
    /// up in one call. This test locks in that semantic contract.
    #[test]
    fn add_association_duplicate_creates_two_entries() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let assoc = Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        };
        graph.add_association(assoc.clone());
        graph.add_association(assoc);
        let found = graph.associations_for_ua(ua_id);
        assert_eq!(found.len(), 2);
        // remove_association should clean up both entries
        graph.remove_association(ua_id, &AssociationTarget::ObjectAttribute(oa_id));
        assert!(graph.associations_for_ua(ua_id).is_empty());
    }

    /// Adding two associations with the same (ua_id, target) but different
    /// operations creates two separate entries — `add_association` appends
    /// unconditionally and does NOT merge or replace.
    #[test]
    fn add_association_same_target_different_ops_creates_two() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["write".to_string()]),
        });
        let found = graph.associations_for_ua(ua_id);
        assert_eq!(found.len(), 2);
    }

    // --- remove_association tests ---

    #[test]
    fn remove_association_removes_matching_association() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.remove_association(ua_id, &AssociationTarget::ObjectAttribute(oa_id));
        let found = graph.associations_for_ua(ua_id);
        assert!(found.is_empty());
    }

    #[test]
    fn remove_association_leaves_other_associations_intact() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id1 = Uuid::new_v4();
        let oa_id2 = Uuid::new_v4();
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id1),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id2),
            operations: HashSet::from(["write".to_string()]),
        });
        graph.remove_association(ua_id, &AssociationTarget::ObjectAttribute(oa_id1));
        let found = graph.associations_for_ua(ua_id);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target, AssociationTarget::ObjectAttribute(oa_id2));
    }

    #[test]
    fn remove_association_noop_when_not_found() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        // Should not panic or error — just a no-op
        graph.remove_association(ua_id, &AssociationTarget::ObjectAttribute(oa_id));
        assert!(graph.associations_for_ua(ua_id).is_empty());
    }

    #[test]
    fn remove_association_matches_on_both_ua_id_and_target() {
        let mut graph = PolicyGraph::new();
        let ua_id1 = Uuid::new_v4();
        let ua_id2 = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        graph.add_association(Association {
            ua_id: ua_id1,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id: ua_id2,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["write".to_string()]),
        });
        // Remove only ua_id1's association to oa_id
        graph.remove_association(ua_id1, &AssociationTarget::ObjectAttribute(oa_id));
        assert!(graph.associations_for_ua(ua_id1).is_empty());
        assert_eq!(graph.associations_for_ua(ua_id2).len(), 1);
    }

    // --- assign_oa_to_pc tests ---

    #[test]
    fn assign_oa_to_pc_creates_assignment() {
        let mut graph = PolicyGraph::new();
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        graph.add_oa(oa.clone());
        graph.add_pc(pc.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        let oas = graph.oas_for_pc(pc.id, "job");
        assert_eq!(oas.len(), 1);
        assert_eq!(oas[0].id, oa.id);
    }

    #[test]
    fn assign_oa_to_pc_duplicate_is_noop() {
        let mut graph = PolicyGraph::new();
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        graph.add_oa(oa.clone());
        graph.add_pc(pc.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        graph.assign_oa_to_pc(oa.id, pc.id); // duplicate
        let oas = graph.oas_for_pc(pc.id, "job");
        assert_eq!(oas.len(), 1);
    }

    #[test]
    fn assign_multiple_oas_to_same_pc() {
        let mut graph = PolicyGraph::new();
        let oa1 = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa2 = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "beta_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        graph.add_oa(oa1.clone());
        graph.add_oa(oa2.clone());
        graph.add_pc(pc.clone());
        graph.assign_oa_to_pc(oa1.id, pc.id);
        graph.assign_oa_to_pc(oa2.id, pc.id);
        let oas = graph.oas_for_pc(pc.id, "job");
        assert_eq!(oas.len(), 2);
    }

    // --- unassign_oa_from_pc tests ---

    #[test]
    fn unassign_oa_from_pc_removes_assignment() {
        let mut graph = PolicyGraph::new();
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        graph.add_oa(oa.clone());
        graph.add_pc(pc.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        graph.unassign_oa_from_pc(oa.id, pc.id);
        let oas = graph.oas_for_pc(pc.id, "job");
        assert!(oas.is_empty());
    }

    #[test]
    fn unassign_oa_from_pc_noop_when_not_assigned() {
        let mut graph = PolicyGraph::new();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        // Should not panic — just a no-op
        graph.unassign_oa_from_pc(oa_id, pc_id);
        assert!(graph.oas_for_pc(pc_id, "job").is_empty());
    }

    #[test]
    fn unassign_oa_from_pc_leaves_other_assignments_intact() {
        let mut graph = PolicyGraph::new();
        let oa1 = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa2 = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "beta_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        graph.add_oa(oa1.clone());
        graph.add_oa(oa2.clone());
        graph.add_pc(pc.clone());
        graph.assign_oa_to_pc(oa1.id, pc.id);
        graph.assign_oa_to_pc(oa2.id, pc.id);
        graph.unassign_oa_from_pc(oa1.id, pc.id);
        let oas = graph.oas_for_pc(pc.id, "job");
        assert_eq!(oas.len(), 1);
        assert_eq!(oas[0].id, oa2.id);
    }

    // --- PolicyGraph serde roundtrip with data ---

    #[test]
    fn policy_graph_serde_roundtrip_with_data() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa.clone());
        graph.add_pc(pc.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa.id),
            operations: HashSet::from(["read".to_string()]),
        });

        let json = serde_json::to_string(&graph).unwrap();
        let deserialized: PolicyGraph = serde_json::from_str(&json).unwrap();

        // Verify data survived roundtrip
        let matching = deserialized.matching_uas(&HashMap::new());
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].id, ua.id);
        assert!(deserialized.get_oa(oa.id).is_some());
        let oas = deserialized.oas_for_pc(pc.id, "job");
        assert_eq!(oas.len(), 1);
        let assocs = deserialized.associations_for_ua(ua.id);
        assert_eq!(assocs.len(), 1);
    }
}
