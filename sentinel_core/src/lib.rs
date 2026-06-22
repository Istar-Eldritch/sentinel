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
    /// Wildcard matcher — matches any attribute set unconditionally, including
    /// the **empty map**.
    ///
    /// # Security note — unauthenticated subjects
    ///
    /// An `All`-matcher [`UserAttribute`] matches a subject that carries *no*
    /// attributes, which is indistinguishable from an unauthenticated request.
    /// Applications **must** enforce authentication before calling
    /// [`evaluate`] or `scope` for non-public resources. Use `All`-matcher
    /// UAs only for genuinely public resources that every caller — including
    /// unauthenticated ones — may access.
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
    /// - [`AttributeMatcher::Matching`] returns `true` when `attrs` contains
    ///   `key` and the value-set for that key has a **non-empty intersection**
    ///   with the matcher's `values` (D18 semantics).
    /// - A key mapped to an **empty set** behaves exactly like an absent key
    ///   (fail-closed: `any` over an empty set is `false`).
    pub fn matches(&self, attrs: &HashMap<String, HashSet<String>>) -> bool {
        match self {
            AttributeMatcher::All => true,
            AttributeMatcher::Matching { key, values } => attrs
                .get(key)
                .is_some_and(|vs| vs.iter().any(|v| values.contains(v))),
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
/// (`evaluate` and `scope`) so they can be written generically over
/// any policy graph implementation. The primary concrete implementation is
/// [`PolicyGraph`].
pub trait PolicyView {
    /// Returns all user attributes whose matcher matches the given subject attributes.
    ///
    /// Subject attributes are multi-valued (D18): each key maps to a
    /// `HashSet<String>`. Iterates over every [`UserAttribute`] in the graph
    /// and returns those where `matcher.matches(subject_attrs)` is `true`.
    fn matching_uas(&self, subject_attrs: &HashMap<String, HashSet<String>>)
    -> Vec<&UserAttribute>;

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

    /// Upserts an association into the graph.
    ///
    /// If an association with the same `(ua_id, target)` pair already exists,
    /// it is **replaced** by the new entry — the second add's operation set
    /// wins (D19 upsert semantics). This ensures exactly one association exists
    /// per `(ua_id, target)` pair at all times, making event-log replay
    /// coherent: replaying `AssociationCreated` for the same pair is
    /// idempotent with respect to count.
    ///
    /// Validation (e.g., ensuring the UA and target exist) is the
    /// responsibility of the aggregate command handler.
    pub fn add_association(&mut self, assoc: Association) {
        self.associations
            .retain(|a| !(a.ua_id == assoc.ua_id && a.target == assoc.target));
        self.associations.push(assoc);
    }

    /// Removes the association matching the given `ua_id` and `target`.
    ///
    /// Because [`Self::add_association`] upserts (at most one entry per
    /// `(ua_id, target)` pair), this removes at most one entry. If no
    /// matching association exists, this is a no-op.
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

    /// Removes a user attribute from the graph and cascades to dependent edges.
    ///
    /// All associations where `ua_id == id` are also removed. Deleting a UA
    /// that does not exist is a no-op.
    pub fn remove_ua(&mut self, id: Uuid) {
        self.user_attributes.remove(&id);
        self.associations.retain(|a| a.ua_id != id);
    }

    /// Removes an object attribute from the graph and cascades to dependent edges.
    ///
    /// All associations targeting this OA and all `oa_pc_assignments` entries
    /// where `oa_id == id` are also removed. Deleting an OA that does not
    /// exist is a no-op.
    pub fn remove_oa(&mut self, id: Uuid) {
        self.object_attributes.remove(&id);
        self.associations
            .retain(|a| a.target != AssociationTarget::ObjectAttribute(id));
        self.oa_pc_assignments.retain(|(oa_id, _)| *oa_id != id);
    }

    /// Removes a policy class from the graph and cascades to dependent edges.
    ///
    /// All associations targeting this PC and all `oa_pc_assignments` entries
    /// where `pc_id == id` are also removed. Deleting a PC that does not
    /// exist is a no-op.
    pub fn remove_pc(&mut self, id: Uuid) {
        self.policy_classes.remove(&id);
        self.associations
            .retain(|a| a.target != AssociationTarget::PolicyClass(id));
        self.oa_pc_assignments.retain(|(_, pc_id)| *pc_id != id);
    }
}

impl Default for PolicyGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyView for PolicyGraph {
    fn matching_uas(
        &self,
        subject_attrs: &HashMap<String, HashSet<String>>,
    ) -> Vec<&UserAttribute> {
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

// ---------------------------------------------------------------------------
// PEP types and functions (Feature 3 — evaluate)
// ---------------------------------------------------------------------------

/// The outcome of a point authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The subject may perform the operation on the resource.
    Allow,
    /// The subject may not perform the operation on the resource.
    Deny,
}

/// A point-check request.
///
/// Chained setters keep the API open for future fields (e.g. environment
/// attributes) without breaking changes (epic R9). Required fields
/// (`operation`, `resource_type`) are constructor arguments — an
/// operation-less request is unrepresentable. There is no `.build()`;
/// the struct is its own builder.
///
/// Attribute maps are multi-valued (`HashMap<String, HashSet<String>>`) per
/// D18 and default to empty (fail-closed) until set.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    subject_attrs: HashMap<String, HashSet<String>>,
    operation: String,
    resource_type: String,
    resource_attrs: HashMap<String, HashSet<String>>,
}

impl AccessRequest {
    /// Creates a new request with the given `operation` and `resource_type`.
    ///
    /// Both attribute maps default to empty, which is fail-closed: a subject
    /// with no attributes will only be granted access through an
    /// `All`-matcher UA (see [`AttributeMatcher::All`] security note).
    pub fn new(operation: impl Into<String>, resource_type: impl Into<String>) -> Self {
        Self {
            subject_attrs: HashMap::new(),
            operation: operation.into(),
            resource_type: resource_type.into(),
            resource_attrs: HashMap::new(),
        }
    }

    /// Sets the subject's attributes (consuming setter).
    ///
    /// Replaces the previously set (or default-empty) subject attribute map.
    pub fn subject_attrs(self, attrs: HashMap<String, HashSet<String>>) -> Self {
        Self {
            subject_attrs: attrs,
            ..self
        }
    }

    /// Sets the resource's attributes (consuming setter).
    ///
    /// Replaces the previously set (or default-empty) resource attribute map.
    pub fn resource_attrs(self, attrs: HashMap<String, HashSet<String>>) -> Self {
        Self {
            resource_attrs: attrs,
            ..self
        }
    }
}

/// Evaluates whether the subject described by `request` may perform the
/// requested operation on the described resource.
///
/// Returns [`Decision::Allow`] when at least one matching grant path is found;
/// [`Decision::Deny`] otherwise (fail-closed).
///
/// # Algorithm (per D16)
///
/// 1. Collect all UAs whose matcher matches `request.subject_attrs`.
/// 2. For each UA, for each association from that UA:
///    - Skip if the association's operation set does not contain the requested
///      operation.
///    - `ObjectAttribute(oa_id)` target: look up the OA. If it exists, its
///      `resource_type` matches the request, **and** its matcher matches
///      `request.resource_attrs` → return `Allow`. If the OA is missing
///      (dangling reference), skip — fail-closed (REQ-EVAL-005).
///    - `PolicyClass(pc_id)` target: collect all OAs assigned to the PC for
///      the requested `resource_type`; if **any** OA's matcher matches
///      `request.resource_attrs` → return `Allow`. Mere existence of OAs
///      under the PC is not sufficient (D16 Option B, REQ-EVAL-004).
/// 3. Return `Deny`.
pub fn evaluate(view: &impl PolicyView, request: &AccessRequest) -> Decision {
    let uas = view.matching_uas(&request.subject_attrs);
    for ua in uas {
        for assoc in view.associations_for_ua(ua.id) {
            if !assoc.operations.contains(&request.operation) {
                continue;
            }
            match &assoc.target {
                AssociationTarget::ObjectAttribute(oa_id) => {
                    if let Some(oa) = view.get_oa(*oa_id)
                        && oa.resource_type == request.resource_type
                        && oa.matcher.matches(&request.resource_attrs)
                    {
                        return Decision::Allow;
                    }
                    // dangling OA reference — skip, fail-closed (REQ-EVAL-005)
                }
                AssociationTarget::PolicyClass(pc_id) => {
                    let oas = view.oas_for_pc(*pc_id, &request.resource_type);
                    if oas
                        .iter()
                        .any(|oa| oa.matcher.matches(&request.resource_attrs))
                    {
                        return Decision::Allow;
                    }
                }
            }
        }
    }
    Decision::Deny
}

// ---------------------------------------------------------------------------
// PEP types and functions (Feature 4 — scope)
// ---------------------------------------------------------------------------

/// A scope-resolution request for list-query filter injection.
///
/// Chained setters keep the API open for future fields (e.g. environment
/// attributes) without breaking changes (epic R9). Required fields
/// (`operation`, `resource_type`) are constructor arguments — an
/// operation-less request is unrepresentable. There is no `.build()`;
/// the struct is its own builder.
///
/// Subject attributes are multi-valued (`HashMap<String, HashSet<String>>`) per
/// D18 and default to empty (fail-closed) until set.
#[derive(Debug, Clone)]
pub struct ScopeRequest {
    subject_attrs: HashMap<String, HashSet<String>>,
    operation: String,
    resource_type: String,
}

impl ScopeRequest {
    /// Creates a new scope request with the given `operation` and `resource_type`.
    ///
    /// Subject attributes default to empty, which is fail-closed: a subject
    /// with no attributes will only be granted access through an
    /// `All`-matcher UA (see [`AttributeMatcher::All`] security note).
    pub fn new(operation: impl Into<String>, resource_type: impl Into<String>) -> Self {
        Self {
            subject_attrs: HashMap::new(),
            operation: operation.into(),
            resource_type: resource_type.into(),
        }
    }

    /// Sets the subject's attributes (consuming setter).
    ///
    /// Replaces the previously set (or default-empty) subject attribute map.
    pub fn subject_attrs(self, attrs: HashMap<String, HashSet<String>>) -> Self {
        Self {
            subject_attrs: attrs,
            ..self
        }
    }
}

/// One attribute constraint for list-query filter injection.
///
/// A constraint specifies that the resource must have a particular attribute
/// key with a value matching one of the allowed values, translating to a SQL
/// `key IN (values...)` predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeConstraint {
    /// The resource's attribute `key` must have a value in `values`
    /// (translates to SQL `key IN (values...)`).
    Attribute {
        /// The resource attribute key to filter on.
        key: String,
        /// The acceptable values for that key.
        values: Vec<String>,
    },
}

/// The resolved access scope for a `(subject, operation, resource_type)` triple.
///
/// Used to inject filters into list queries so that only authorized resources
/// are returned. Translate the variants as follows:
/// - [`Unrestricted`](AccessScope::Unrestricted): no `WHERE` clause; return all.
/// - [`Constrained`](AccessScope::Constrained): inject the constraints as `WHERE` clauses.
/// - [`None`](AccessScope::None): return an empty result set immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessScope {
    /// No filter needed — the subject may access all resources of this type.
    Unrestricted,
    /// One or more attribute constraints defining the accessible subset.
    ///
    /// # Union semantics
    ///
    /// Constraints are a **union** (OR) of access paths, never an intersection.
    /// Each [`ScopeConstraint`] represents an independent grant; the result set
    /// is the *union* of resources matching *any* constraint. Multi-axis "AND"
    /// policies (e.g., "org alpha AND low-sensitivity") are not expressible via
    /// multiple associations and would inadvertently *broaden* access if attempted.
    Constrained(Vec<ScopeConstraint>),
    /// No access — the application should return an empty result set.
    None,
}

/// Resolves the access scope for the subject described by `request` for
/// list-query filter injection.
///
/// Returns an [`AccessScope`] that can be translated into a database filter.
///
/// # Algorithm (per D16, D17)
///
/// 1. Collect all UAs whose matcher matches `request.subject_attrs`.
/// 2. For each UA, for each association from that UA:
///    - Skip if the operation set does not contain the requested operation.
///    - `ObjectAttribute(oa_id)` target: if the OA exists and its
///      `resource_type` matches the request, push it onto `candidate_oas`.
///      Skip dangling references (fail-closed, mirrors REQ-EVAL-005).
///    - `PolicyClass(pc_id)` target: push **all** OAs assigned to the PC for
///      the requested `resource_type` onto `candidate_oas` (D16 expansion).
///      UA→PC is shorthand for "every OA under that PC", not god-mode.
/// 3. If any candidate OA has `matcher == AttributeMatcher::All`, return
///    `Unrestricted` immediately (D17 short-circuit: `X OR true = true`).
/// 4. For each `Matching { key, values }` matcher (in candidate-first-seen
///    order), group by `key` and union the `values` lists (deduplicating,
///    preserving first-seen value order) → `ScopeConstraint::Attribute`.
/// 5. Return `Constrained(constraints)` if any constraints were collected,
///    otherwise `None`.
pub fn scope(view: &impl PolicyView, request: &ScopeRequest) -> AccessScope {
    let uas = view.matching_uas(&request.subject_attrs);

    // Step 2: collect candidate OAs
    let mut candidate_oas: Vec<&ObjectAttribute> = Vec::new();
    for ua in uas {
        for assoc in view.associations_for_ua(ua.id) {
            if !assoc.operations.contains(&request.operation) {
                continue;
            }
            match &assoc.target {
                AssociationTarget::ObjectAttribute(oa_id) => {
                    if let Some(oa) = view.get_oa(*oa_id)
                        && oa.resource_type == request.resource_type
                    {
                        candidate_oas.push(oa);
                    }
                    // dangling OA reference — skip, fail-closed
                }
                AssociationTarget::PolicyClass(pc_id) => {
                    candidate_oas.extend(view.oas_for_pc(*pc_id, &request.resource_type));
                }
            }
        }
    }

    // Step 3: All-matcher short-circuit (D17)
    if candidate_oas
        .iter()
        .any(|oa| oa.matcher == AttributeMatcher::All)
    {
        return AccessScope::Unrestricted;
    }

    // Step 4: merge Matching matchers by key (first-seen key order, union values)
    let mut key_order: Vec<String> = Vec::new();
    let mut key_values: HashMap<String, Vec<String>> = HashMap::new();

    for oa in &candidate_oas {
        if let AttributeMatcher::Matching { key, values } = &oa.matcher {
            let entry = key_values.entry(key.clone()).or_insert_with(|| {
                key_order.push(key.clone());
                Vec::new()
            });
            for v in values {
                if !entry.contains(v) {
                    entry.push(v.clone());
                }
            }
        }
    }

    // Step 5: build constraints or return None
    if key_order.is_empty() {
        AccessScope::None
    } else {
        let constraints = key_order
            .into_iter()
            .map(|k| {
                let values = key_values.remove(&k).unwrap_or_default();
                ScopeConstraint::Attribute { key: k, values }
            })
            .collect();
        AccessScope::Constrained(constraints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use uuid::Uuid;

    /// Constructs a multi-valued attribute map from key-value pairs.
    ///
    /// Each pair maps a key to one or more string values. Useful for building
    /// `&HashMap<String, HashSet<String>>` arguments in tests concisely.
    fn attrs(pairs: &[(&str, &[&str])]) -> HashMap<String, HashSet<String>> {
        pairs
            .iter()
            .map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect()))
            .collect()
    }

    // --- AttributeMatcher::All tests ---

    #[test]
    fn all_matcher_matches_empty_attrs() {
        let matcher = AttributeMatcher::All;
        assert!(matcher.matches(&HashMap::new()));
    }

    #[test]
    fn all_matcher_matches_any_attrs() {
        let matcher = AttributeMatcher::All;
        let attrs = HashMap::from([("key".to_string(), HashSet::from(["value".to_string()]))]);
        assert!(matcher.matches(&attrs));
    }

    // --- AttributeMatcher::Matching tests ---

    #[test]
    fn matching_matcher_matches_when_key_and_value_present() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        let attrs = HashMap::from([("org_id".to_string(), HashSet::from(["alpha".to_string()]))]);
        assert!(matcher.matches(&attrs));
    }

    #[test]
    fn matching_matcher_no_match_when_key_missing() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        let attrs = HashMap::from([("other".to_string(), HashSet::from(["alpha".to_string()]))]);
        assert!(!matcher.matches(&attrs));
    }

    #[test]
    fn matching_matcher_no_match_when_value_differs() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        let attrs = HashMap::from([("org_id".to_string(), HashSet::from(["beta".to_string()]))]);
        assert!(!matcher.matches(&attrs));
    }

    #[test]
    fn matching_matcher_matches_any_of_multiple_values() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string(), "beta".to_string()],
        };
        let attrs = HashMap::from([("org_id".to_string(), HashSet::from(["beta".to_string()]))]);
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
        let attrs = HashMap::from([("org_id".to_string(), HashSet::from(["alpha".to_string()]))]);
        assert!(!matcher.matches(&attrs));
    }

    // --- D18 multi-valued intersection semantics tests ---

    /// An input key mapped to multiple values matches when at least one
    /// of those values is present in the matcher's `values` list.
    #[test]
    fn matches_multivalued_intersection_match() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        // subject org_id ∈ {alpha, beta} — non-empty intersection with ["alpha"]
        assert!(matcher.matches(&attrs(&[("org_id", &["alpha", "beta"])])));
    }

    /// An input key mapped to values that share no element with the matcher's
    /// `values` list never matches.
    #[test]
    fn matches_multivalued_disjoint_no_match() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        // subject org_id ∈ {gamma} — disjoint from ["alpha"]
        assert!(!matcher.matches(&attrs(&[("org_id", &["gamma"])])));
    }

    /// A key mapped to an empty set never matches — identical to an absent key
    /// (fail-closed: `any` over an empty set is `false`).
    #[test]
    fn matches_empty_set_no_match() {
        let matcher = AttributeMatcher::Matching {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        // org_id → {} behaves the same as org_id absent
        assert!(!matcher.matches(&attrs(&[("org_id", &[])])));
    }

    /// `All` matcher semantics are unchanged under the multi-valued signature:
    /// it matches the empty map and any non-empty map.
    #[test]
    fn all_matcher_unchanged_with_multivalued_signature() {
        let matcher = AttributeMatcher::All;
        assert!(matcher.matches(&HashMap::new()));
        assert!(matcher.matches(&attrs(&[("org_id", &["alpha", "beta"])])));
    }

    /// `matching_uas` respects multi-valued subject attributes (D18):
    /// a subject with `org_id ∈ {alpha, beta}` matches a UA whose
    /// `Matching { key: "org_id", values: ["alpha"] }` matcher is satisfied
    /// by intersection.
    #[test]
    fn matching_uas_multivalued_subject_intersection() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_alpha_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        graph.add_ua(ua.clone());
        // Subject belongs to both alpha and beta — should match via alpha
        let subject = attrs(&[("org_id", &["alpha", "beta"])]);
        let matching = graph.matching_uas(&subject);
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].id, ua.id);
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

    /// Adding the exact same `(ua_id, target)` association twice upserts:
    /// after the second add, exactly **one** association exists for the pair,
    /// carrying the **second** operation set (D19 upsert semantics).
    #[test]
    fn add_association_duplicate_upserts_replacing_existing() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        // First add: {read}
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        // Second add with same (ua_id, target): {write} — replaces, not appends
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["write".to_string()]),
        });
        let found = graph.associations_for_ua(ua_id);
        // Exactly one entry; second add's operation set wins
        assert_eq!(found.len(), 1);
        assert!(found[0].operations.contains("write"));
        assert!(!found[0].operations.contains("read"));
    }

    /// Two adds with same `(ua_id, target)` but different operations upsert:
    /// exactly one entry remains; the second operation set wins.
    #[test]
    fn add_association_same_target_upserts_second_wins() {
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
        // Upsert: exactly one entry; second operation set wins
        assert_eq!(found.len(), 1);
        assert!(found[0].operations.contains("write"));
        assert!(!found[0].operations.contains("read"));
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

    // --- remove_ua tests ---

    #[test]
    fn remove_ua_removes_user_attribute() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.remove_ua(ua.id);
        assert!(graph.matching_uas(&HashMap::new()).is_empty());
    }

    #[test]
    fn remove_ua_cascades_to_associations() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.remove_ua(ua_id);
        assert!(graph.associations_for_ua(ua_id).is_empty());
    }

    #[test]
    fn remove_ua_cascade_leaves_other_ua_associations_intact() {
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
        graph.remove_ua(ua_id1);
        assert!(graph.associations_for_ua(ua_id1).is_empty());
        assert_eq!(graph.associations_for_ua(ua_id2).len(), 1);
    }

    #[test]
    fn remove_ua_noop_when_not_found() {
        let mut graph = PolicyGraph::new();
        graph.remove_ua(Uuid::new_v4()); // must not panic
        assert!(graph.matching_uas(&HashMap::new()).is_empty());
    }

    // --- remove_oa tests ---

    #[test]
    fn remove_oa_removes_object_attribute() {
        let mut graph = PolicyGraph::new();
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_oa(oa.clone());
        graph.remove_oa(oa.id);
        assert!(graph.get_oa(oa.id).is_none());
    }

    #[test]
    fn remove_oa_cascades_to_associations() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.remove_oa(oa_id);
        assert!(graph.associations_for_ua(ua_id).is_empty());
    }

    #[test]
    fn remove_oa_cascade_leaves_other_oa_associations_intact() {
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
        graph.remove_oa(oa_id1);
        let found = graph.associations_for_ua(ua_id);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target, AssociationTarget::ObjectAttribute(oa_id2));
    }

    #[test]
    fn remove_oa_cascades_to_oa_pc_assignments() {
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
        graph.remove_oa(oa.id);
        assert!(graph.oas_for_pc(pc.id, "job").is_empty());
    }

    #[test]
    fn remove_oa_cascade_leaves_other_oa_assignments_intact() {
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
        graph.remove_oa(oa1.id);
        let oas = graph.oas_for_pc(pc.id, "job");
        assert_eq!(oas.len(), 1);
        assert_eq!(oas[0].id, oa2.id);
    }

    #[test]
    fn remove_oa_noop_when_not_found() {
        let mut graph = PolicyGraph::new();
        graph.remove_oa(Uuid::new_v4()); // must not panic
    }

    // --- remove_pc tests ---

    #[test]
    fn remove_pc_removes_policy_class() {
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
        graph.remove_pc(pc.id);
        // oas_for_pc uses the assignment set; if PC is gone, no OAs returned
        assert!(graph.oas_for_pc(pc.id, "job").is_empty());
    }

    #[test]
    fn remove_pc_cascades_to_associations() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::PolicyClass(pc_id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.remove_pc(pc_id);
        assert!(graph.associations_for_ua(ua_id).is_empty());
    }

    #[test]
    fn remove_pc_cascade_leaves_other_pc_associations_intact() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let pc_id1 = Uuid::new_v4();
        let pc_id2 = Uuid::new_v4();
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::PolicyClass(pc_id1),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::PolicyClass(pc_id2),
            operations: HashSet::from(["write".to_string()]),
        });
        graph.remove_pc(pc_id1);
        let found = graph.associations_for_ua(ua_id);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target, AssociationTarget::PolicyClass(pc_id2));
    }

    #[test]
    fn remove_pc_cascades_to_oa_pc_assignments() {
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
        graph.remove_pc(pc.id);
        assert!(graph.oas_for_pc(pc.id, "job").is_empty());
    }

    #[test]
    fn remove_pc_cascade_leaves_other_pc_assignments_intact() {
        let mut graph = PolicyGraph::new();
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc1 = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_policy".to_string(),
        };
        let pc2 = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        graph.add_oa(oa.clone());
        graph.add_pc(pc1.clone());
        graph.add_pc(pc2.clone());
        graph.assign_oa_to_pc(oa.id, pc1.id);
        graph.assign_oa_to_pc(oa.id, pc2.id);
        graph.remove_pc(pc1.id);
        assert!(graph.oas_for_pc(pc1.id, "job").is_empty());
        assert_eq!(graph.oas_for_pc(pc2.id, "job").len(), 1);
    }

    #[test]
    fn remove_pc_noop_when_not_found() {
        let mut graph = PolicyGraph::new();
        graph.remove_pc(Uuid::new_v4()); // must not panic
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

    // =========================================================
    // PolicyView comprehensive query tests (Phase 5)
    // =========================================================

    // --- matching_uas query tests ---

    /// With multiple UAs (some All, some Matching), `matching_uas` returns
    /// only those whose matcher matches the given subject attributes.
    #[test]
    fn matching_uas_returns_only_matching_uas() {
        let mut graph = PolicyGraph::new();
        let ua_all = UserAttribute {
            id: Uuid::new_v4(),
            name: "everyone".to_string(),
            matcher: AttributeMatcher::All,
        };
        let ua_alpha = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_alpha_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let ua_beta = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_beta_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["beta".to_string()],
            },
        };
        graph.add_ua(ua_all.clone());
        graph.add_ua(ua_alpha.clone());
        graph.add_ua(ua_beta.clone());

        let alpha_subject =
            HashMap::from([("org_id".to_string(), HashSet::from(["alpha".to_string()]))]);
        let matching = graph.matching_uas(&alpha_subject);

        // Should match: ua_all (All always matches) and ua_alpha (org_id=alpha)
        // Should NOT match: ua_beta (org_id=beta)
        assert_eq!(matching.len(), 2);
        let ids: HashSet<Uuid> = matching.iter().map(|ua| ua.id).collect();
        assert!(ids.contains(&ua_all.id));
        assert!(ids.contains(&ua_alpha.id));
        assert!(!ids.contains(&ua_beta.id));
    }

    /// `matching_uas` with an `All` matcher UA always includes it regardless
    /// of what subject attributes are provided.
    #[test]
    fn matching_uas_all_matcher_always_included() {
        let mut graph = PolicyGraph::new();
        let ua_all = UserAttribute {
            id: Uuid::new_v4(),
            name: "everyone".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua_all.clone());

        // Empty attrs
        let m1 = graph.matching_uas(&HashMap::new());
        assert_eq!(m1.len(), 1);
        assert_eq!(m1[0].id, ua_all.id);

        // Arbitrary attrs
        let m2 = graph.matching_uas(&HashMap::from([(
            "org_id".to_string(),
            HashSet::from(["whatever".to_string()]),
        )]));
        assert_eq!(m2.len(), 1);
        assert_eq!(m2[0].id, ua_all.id);
    }

    /// When no UAs match the given subject attributes, `matching_uas`
    /// returns an empty vector.
    #[test]
    fn matching_uas_returns_empty_when_no_match() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_alpha_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        graph.add_ua(ua);

        let gamma_subject =
            HashMap::from([("org_id".to_string(), HashSet::from(["gamma".to_string()]))]);
        assert!(graph.matching_uas(&gamma_subject).is_empty());
    }

    /// When multiple UAs all match (e.g., multiple `All` matchers),
    /// `matching_uas` returns all of them.
    #[test]
    fn matching_uas_returns_all_matching_uas() {
        let mut graph = PolicyGraph::new();
        let ua1 = UserAttribute {
            id: Uuid::new_v4(),
            name: "everyone".to_string(),
            matcher: AttributeMatcher::All,
        };
        let ua2 = UserAttribute {
            id: Uuid::new_v4(),
            name: "also_everyone".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua1.clone());
        graph.add_ua(ua2.clone());

        let matching = graph.matching_uas(&HashMap::new());
        assert_eq!(matching.len(), 2);
    }

    /// A `Matching` UA with multiple values matches any of them.
    #[test]
    fn matching_uas_multi_value_matcher() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "multi_org".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()],
            },
        };
        graph.add_ua(ua.clone());

        let beta_subject =
            HashMap::from([("org_id".to_string(), HashSet::from(["beta".to_string()]))]);
        let matching = graph.matching_uas(&beta_subject);
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].id, ua.id);
    }

    /// Subject with extra attributes beyond what the matcher checks still
    /// matches — the matcher only inspects its own key.
    #[test]
    fn matching_uas_ignores_extra_subject_attrs() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_alpha_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        graph.add_ua(ua.clone());

        let subject_with_extras = HashMap::from([
            ("org_id".to_string(), HashSet::from(["alpha".to_string()])),
            ("role".to_string(), HashSet::from(["admin".to_string()])),
            (
                "department".to_string(),
                HashSet::from(["engineering".to_string()]),
            ),
        ]);
        let matching = graph.matching_uas(&subject_with_extras);
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].id, ua.id);
    }

    // --- associations_for_ua query tests ---

    /// `associations_for_ua` returns only associations for the given UA,
    /// not associations belonging to other UAs.
    #[test]
    fn associations_for_ua_filters_by_ua_id() {
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

        let assocs1 = graph.associations_for_ua(ua_id1);
        assert_eq!(assocs1.len(), 1);
        assert!(assocs1[0].operations.contains("read"));

        let assocs2 = graph.associations_for_ua(ua_id2);
        assert_eq!(assocs2.len(), 1);
        assert!(assocs2[0].operations.contains("write"));
    }

    /// `associations_for_ua` returns empty vec for a UA with no associations.
    #[test]
    fn associations_for_ua_empty_for_unknown_ua() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let other_ua_id = Uuid::new_v4();
        graph.add_association(Association {
            ua_id: other_ua_id,
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::from(["read".to_string()]),
        });

        assert!(graph.associations_for_ua(ua_id).is_empty());
    }

    /// A single UA can have associations to both OA and PC targets;
    /// `associations_for_ua` returns all of them.
    #[test]
    fn associations_for_ua_returns_mixed_target_types() {
        let mut graph = PolicyGraph::new();
        let ua_id = Uuid::new_v4();
        let oa_id = Uuid::new_v4();
        let pc_id = Uuid::new_v4();
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::ObjectAttribute(oa_id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id,
            target: AssociationTarget::PolicyClass(pc_id),
            operations: HashSet::from(["admin".to_string()]),
        });

        let assocs = graph.associations_for_ua(ua_id);
        assert_eq!(assocs.len(), 2);
        let targets: Vec<&AssociationTarget> = assocs.iter().map(|a| &a.target).collect();
        assert!(targets.contains(&&AssociationTarget::ObjectAttribute(oa_id)));
        assert!(targets.contains(&&AssociationTarget::PolicyClass(pc_id)));
    }

    // --- get_oa query tests ---

    /// `get_oa` returns `Some` for an existing OA and `None` for a missing one.
    #[test]
    fn get_oa_returns_correct_oa_among_multiple() {
        let mut graph = PolicyGraph::new();
        let oa1 = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let oa2 = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "beta_docs".to_string(),
            resource_type: "document".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_oa(oa1.clone());
        graph.add_oa(oa2.clone());

        let found1 = graph.get_oa(oa1.id);
        assert!(found1.is_some());
        assert_eq!(found1.unwrap().name, "alpha_jobs");
        assert_eq!(found1.unwrap().resource_type, "job");

        let found2 = graph.get_oa(oa2.id);
        assert!(found2.is_some());
        assert_eq!(found2.unwrap().name, "beta_docs");

        // Non-existent OA
        assert!(graph.get_oa(Uuid::new_v4()).is_none());
    }

    /// `get_oa` on an empty graph always returns `None`.
    #[test]
    fn get_oa_none_on_empty_graph() {
        let graph = PolicyGraph::new();
        assert!(graph.get_oa(Uuid::new_v4()).is_none());
    }

    // --- oas_for_pc query tests ---

    /// `oas_for_pc` filters by resource_type, returning only OAs of the
    /// requested type even when multiple types are assigned to the same PC.
    #[test]
    fn oas_for_pc_filters_by_resource_type() {
        let mut graph = PolicyGraph::new();
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        let oa_job = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "all_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa_doc = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "all_docs".to_string(),
            resource_type: "document".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_pc(pc.clone());
        graph.add_oa(oa_job.clone());
        graph.add_oa(oa_doc.clone());
        graph.assign_oa_to_pc(oa_job.id, pc.id);
        graph.assign_oa_to_pc(oa_doc.id, pc.id);

        let jobs = graph.oas_for_pc(pc.id, "job");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, oa_job.id);

        let docs = graph.oas_for_pc(pc.id, "document");
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].id, oa_doc.id);

        // Non-existent resource type
        let widgets = graph.oas_for_pc(pc.id, "widget");
        assert!(widgets.is_empty());
    }

    /// `oas_for_pc` does not return OAs assigned to a different PC.
    #[test]
    fn oas_for_pc_filters_by_pc_id() {
        let mut graph = PolicyGraph::new();
        let pc1 = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_alpha_policy".to_string(),
        };
        let pc2 = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_beta_policy".to_string(),
        };
        let oa_alpha = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let oa_beta = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "beta_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["beta".to_string()],
            },
        };
        graph.add_pc(pc1.clone());
        graph.add_pc(pc2.clone());
        graph.add_oa(oa_alpha.clone());
        graph.add_oa(oa_beta.clone());
        graph.assign_oa_to_pc(oa_alpha.id, pc1.id);
        graph.assign_oa_to_pc(oa_beta.id, pc2.id);

        let alpha_jobs = graph.oas_for_pc(pc1.id, "job");
        assert_eq!(alpha_jobs.len(), 1);
        assert_eq!(alpha_jobs[0].id, oa_alpha.id);

        let beta_jobs = graph.oas_for_pc(pc2.id, "job");
        assert_eq!(beta_jobs.len(), 1);
        assert_eq!(beta_jobs[0].id, oa_beta.id);
    }

    /// An OA that exists in the graph but is not assigned to any PC
    /// should not appear in `oas_for_pc` results.
    #[test]
    fn oas_for_pc_excludes_unassigned_oas() {
        let mut graph = PolicyGraph::new();
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_policy".to_string(),
        };
        let oa_assigned = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "assigned_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa_unassigned = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "unassigned_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_pc(pc.clone());
        graph.add_oa(oa_assigned.clone());
        graph.add_oa(oa_unassigned.clone());
        graph.assign_oa_to_pc(oa_assigned.id, pc.id);
        // oa_unassigned is NOT assigned to any PC

        let jobs = graph.oas_for_pc(pc.id, "job");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, oa_assigned.id);
    }

    /// `oas_for_pc` with a non-existent PC ID returns empty.
    #[test]
    fn oas_for_pc_empty_for_nonexistent_pc() {
        let mut graph = PolicyGraph::new();
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_oa(oa.clone());
        // No PC added, no assignment made

        assert!(graph.oas_for_pc(Uuid::new_v4(), "job").is_empty());
    }

    /// An OA can be assigned to multiple PCs and should appear in
    /// `oas_for_pc` for each of them.
    #[test]
    fn oas_for_pc_oa_assigned_to_multiple_pcs() {
        let mut graph = PolicyGraph::new();
        let pc1 = PolicyClass {
            id: Uuid::new_v4(),
            name: "policy_a".to_string(),
        };
        let pc2 = PolicyClass {
            id: Uuid::new_v4(),
            name: "policy_b".to_string(),
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "shared_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_pc(pc1.clone());
        graph.add_pc(pc2.clone());
        graph.add_oa(oa.clone());
        graph.assign_oa_to_pc(oa.id, pc1.id);
        graph.assign_oa_to_pc(oa.id, pc2.id);

        let from_pc1 = graph.oas_for_pc(pc1.id, "job");
        assert_eq!(from_pc1.len(), 1);
        assert_eq!(from_pc1[0].id, oa.id);

        let from_pc2 = graph.oas_for_pc(pc2.id, "job");
        assert_eq!(from_pc2.len(), 1);
        assert_eq!(from_pc2[0].id, oa.id);
    }

    // --- End-to-end PolicyView scenario test ---

    /// Realistic scenario: Two organizations (alpha, beta) with different
    /// resource types (jobs, documents). Verifies all four PolicyView
    /// methods work together on a multi-org, multi-resource-type graph.
    #[test]
    fn policy_view_multi_org_scenario() {
        let mut graph = PolicyGraph::new();

        // --- Policy classes (one per org) ---
        let pc_alpha = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_alpha_policy".to_string(),
        };
        let pc_beta = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_beta_policy".to_string(),
        };
        graph.add_pc(pc_alpha.clone());
        graph.add_pc(pc_beta.clone());

        // --- User attributes ---
        let ua_alpha_members = UserAttribute {
            id: Uuid::new_v4(),
            name: "alpha_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let ua_beta_members = UserAttribute {
            id: Uuid::new_v4(),
            name: "beta_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["beta".to_string()],
            },
        };
        let ua_admins = UserAttribute {
            id: Uuid::new_v4(),
            name: "platform_admins".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "role".to_string(),
                values: vec!["admin".to_string()],
            },
        };
        graph.add_ua(ua_alpha_members.clone());
        graph.add_ua(ua_beta_members.clone());
        graph.add_ua(ua_admins.clone());

        // --- Object attributes ---
        let oa_alpha_jobs = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let oa_beta_jobs = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "beta_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["beta".to_string()],
            },
        };
        let oa_alpha_docs = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_docs".to_string(),
            resource_type: "document".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        graph.add_oa(oa_alpha_jobs.clone());
        graph.add_oa(oa_beta_jobs.clone());
        graph.add_oa(oa_alpha_docs.clone());

        // --- OA→PC assignments ---
        graph.assign_oa_to_pc(oa_alpha_jobs.id, pc_alpha.id);
        graph.assign_oa_to_pc(oa_alpha_docs.id, pc_alpha.id);
        graph.assign_oa_to_pc(oa_beta_jobs.id, pc_beta.id);

        // --- Associations ---
        graph.add_association(Association {
            ua_id: ua_alpha_members.id,
            target: AssociationTarget::ObjectAttribute(oa_alpha_jobs.id),
            operations: HashSet::from(["read".to_string(), "write".to_string()]),
        });
        graph.add_association(Association {
            ua_id: ua_alpha_members.id,
            target: AssociationTarget::ObjectAttribute(oa_alpha_docs.id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id: ua_beta_members.id,
            target: AssociationTarget::ObjectAttribute(oa_beta_jobs.id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id: ua_admins.id,
            target: AssociationTarget::PolicyClass(pc_alpha.id),
            operations: HashSet::from([
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
            ]),
        });

        // --- Verify: matching_uas ---
        // An alpha member should match ua_alpha_members only
        let alpha_subject =
            HashMap::from([("org_id".to_string(), HashSet::from(["alpha".to_string()]))]);
        let alpha_uas = graph.matching_uas(&alpha_subject);
        assert_eq!(alpha_uas.len(), 1);
        assert_eq!(alpha_uas[0].id, ua_alpha_members.id);

        // A platform admin (not in any org) should match ua_admins only
        let admin_subject =
            HashMap::from([("role".to_string(), HashSet::from(["admin".to_string()]))]);
        let admin_uas = graph.matching_uas(&admin_subject);
        assert_eq!(admin_uas.len(), 1);
        assert_eq!(admin_uas[0].id, ua_admins.id);

        // An alpha admin matches both ua_alpha_members and ua_admins
        let alpha_admin_subject = HashMap::from([
            ("org_id".to_string(), HashSet::from(["alpha".to_string()])),
            ("role".to_string(), HashSet::from(["admin".to_string()])),
        ]);
        let alpha_admin_uas = graph.matching_uas(&alpha_admin_subject);
        assert_eq!(alpha_admin_uas.len(), 2);
        let ua_ids: HashSet<Uuid> = alpha_admin_uas.iter().map(|ua| ua.id).collect();
        assert!(ua_ids.contains(&ua_alpha_members.id));
        assert!(ua_ids.contains(&ua_admins.id));

        // A user in org "gamma" matches no UAs
        let gamma_subject =
            HashMap::from([("org_id".to_string(), HashSet::from(["gamma".to_string()]))]);
        assert!(graph.matching_uas(&gamma_subject).is_empty());

        // --- Verify: associations_for_ua ---
        // Alpha members have 2 associations (alpha_jobs + alpha_docs)
        let alpha_assocs = graph.associations_for_ua(ua_alpha_members.id);
        assert_eq!(alpha_assocs.len(), 2);

        // Beta members have 1 association (beta_jobs)
        let beta_assocs = graph.associations_for_ua(ua_beta_members.id);
        assert_eq!(beta_assocs.len(), 1);
        assert_eq!(
            beta_assocs[0].target,
            AssociationTarget::ObjectAttribute(oa_beta_jobs.id)
        );

        // Admins have 1 association (to pc_alpha)
        let admin_assocs = graph.associations_for_ua(ua_admins.id);
        assert_eq!(admin_assocs.len(), 1);
        assert_eq!(
            admin_assocs[0].target,
            AssociationTarget::PolicyClass(pc_alpha.id)
        );
        assert!(admin_assocs[0].operations.contains("delete"));

        // --- Verify: get_oa ---
        let oa = graph.get_oa(oa_alpha_jobs.id).unwrap();
        assert_eq!(oa.name, "alpha_jobs");
        assert_eq!(oa.resource_type, "job");

        let oa_doc = graph.get_oa(oa_alpha_docs.id).unwrap();
        assert_eq!(oa_doc.resource_type, "document");

        assert!(graph.get_oa(Uuid::new_v4()).is_none());

        // --- Verify: oas_for_pc ---
        // Alpha PC has alpha_jobs (job) and alpha_docs (document)
        let alpha_pc_jobs = graph.oas_for_pc(pc_alpha.id, "job");
        assert_eq!(alpha_pc_jobs.len(), 1);
        assert_eq!(alpha_pc_jobs[0].id, oa_alpha_jobs.id);

        let alpha_pc_docs = graph.oas_for_pc(pc_alpha.id, "document");
        assert_eq!(alpha_pc_docs.len(), 1);
        assert_eq!(alpha_pc_docs[0].id, oa_alpha_docs.id);

        // Beta PC has beta_jobs only
        let beta_pc_jobs = graph.oas_for_pc(pc_beta.id, "job");
        assert_eq!(beta_pc_jobs.len(), 1);
        assert_eq!(beta_pc_jobs[0].id, oa_beta_jobs.id);

        // Beta PC has no documents
        assert!(graph.oas_for_pc(pc_beta.id, "document").is_empty());
    }

    // =========================================================
    // Phase 3 — evaluate() tests (REQ-EVAL-001…005, REQ-DOC-001)
    // =========================================================

    // ---- Fixture helpers ----

    /// Builds a minimal graph for evaluate() tests:
    ///
    /// - `ua_alpha_members`: Matching { org_id ∈ ["alpha"] }
    /// - `oa_alpha_jobs`: resource_type="job", Matching { org_id ∈ ["alpha"] }
    /// - `assoc`: (ua_alpha_members → oa_alpha_jobs, {"read"})
    ///
    /// Returns (graph, ua_id, oa_id).
    fn eval_basic_graph() -> (PolicyGraph, Uuid, Uuid) {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "alpha_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
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
        graph.add_ua(ua.clone());
        graph.add_oa(oa.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa.id),
            operations: HashSet::from(["read".to_string()]),
        });
        (graph, ua.id, oa.id)
    }

    // ---- AccessRequest type-shape tests ----

    /// `AccessRequest::new` yields empty attribute maps (fail-closed defaults).
    #[test]
    fn access_request_new_has_empty_attrs() {
        let req = AccessRequest::new("read", "job");
        assert_eq!(req.operation, "read");
        assert_eq!(req.resource_type, "job");
        assert!(req.subject_attrs.is_empty());
        assert!(req.resource_attrs.is_empty());
    }

    /// Consuming setters can be chained in either order.
    #[test]
    fn access_request_setters_chain_in_any_order() {
        let s = attrs(&[("role", &["admin"])]);
        let r = attrs(&[("org_id", &["alpha"])]);
        let req1 = AccessRequest::new("write", "doc")
            .subject_attrs(s.clone())
            .resource_attrs(r.clone());
        let req2 = AccessRequest::new("write", "doc")
            .resource_attrs(r.clone())
            .subject_attrs(s.clone());
        assert_eq!(req1.subject_attrs, req2.subject_attrs);
        assert_eq!(req1.resource_attrs, req2.resource_attrs);
    }

    /// Empty subject attrs against a non-All graph → Deny (fail-closed).
    #[test]
    fn evaluate_empty_subject_attrs_against_non_all_graph_is_deny() {
        let (graph, _, _) = eval_basic_graph();
        // No subject attributes provided — can't match Matching UA
        let req = AccessRequest::new("read", "job");
        assert_eq!(evaluate(&graph, &req), Decision::Deny);
    }

    // ---- evaluate() core behavior tests (REQ-EVAL-003) ----

    /// Allow via UA→OA: matching UA, association with the operation, OA with
    /// matching resource_type and matcher.
    #[test]
    fn evaluate_allows_via_ua_oa_match() {
        let (graph, _, _) = eval_basic_graph();
        let req = AccessRequest::new("read", "job")
            .subject_attrs(attrs(&[("org_id", &["alpha"])]))
            .resource_attrs(attrs(&[("org_id", &["alpha"])]));
        assert_eq!(evaluate(&graph, &req), Decision::Allow);
    }

    /// Deny when the operation is absent from the association's operation set.
    #[test]
    fn evaluate_denies_when_operation_absent() {
        let (graph, _, _) = eval_basic_graph();
        // Association only carries "read"; request asks for "write"
        let req = AccessRequest::new("write", "job")
            .subject_attrs(attrs(&[("org_id", &["alpha"])]))
            .resource_attrs(attrs(&[("org_id", &["alpha"])]));
        assert_eq!(evaluate(&graph, &req), Decision::Deny);
    }

    /// Deny when no UA matches the subject attributes.
    #[test]
    fn evaluate_denies_when_no_ua_matches() {
        let (graph, _, _) = eval_basic_graph();
        // Subject is in org "gamma", but the only UA matches "alpha"
        let req = AccessRequest::new("read", "job")
            .subject_attrs(attrs(&[("org_id", &["gamma"])]))
            .resource_attrs(attrs(&[("org_id", &["gamma"])]));
        assert_eq!(evaluate(&graph, &req), Decision::Deny);
    }

    /// Deny when the OA's resource_type does not match the request's resource_type.
    #[test]
    fn evaluate_denies_on_resource_type_mismatch() {
        let (graph, _, _) = eval_basic_graph();
        // OA is "job" but request asks for "document"
        let req = AccessRequest::new("read", "document")
            .subject_attrs(attrs(&[("org_id", &["alpha"])]))
            .resource_attrs(attrs(&[("org_id", &["alpha"])]));
        assert_eq!(evaluate(&graph, &req), Decision::Deny);
    }

    /// Deny when the OA's matcher does not match the resource attributes.
    #[test]
    fn evaluate_denies_when_matcher_does_not_match_resource_attrs() {
        let (graph, _, _) = eval_basic_graph();
        // OA matches org_id ∈ ["alpha"] but resource is in org "beta"
        let req = AccessRequest::new("read", "job")
            .subject_attrs(attrs(&[("org_id", &["alpha"])]))
            .resource_attrs(attrs(&[("org_id", &["beta"])]));
        assert_eq!(evaluate(&graph, &req), Decision::Deny);
    }

    /// D18 multi-valued subject: a subject with org_id ∈ {alpha, beta} is
    /// allowed through an alpha-scoped UA→OA path.
    #[test]
    fn evaluate_allows_multivalued_subject_via_alpha_path() {
        let (graph, _, _) = eval_basic_graph();
        // Subject belongs to both alpha and beta; alpha grants read on alpha jobs
        let req = AccessRequest::new("read", "job")
            .subject_attrs(attrs(&[("org_id", &["alpha", "beta"])]))
            .resource_attrs(attrs(&[("org_id", &["alpha"])]));
        assert_eq!(evaluate(&graph, &req), Decision::Allow);
    }

    /// REQ-DOC-001 sharp edge: an All-matcher UA matches an **empty** subject
    /// attribute map (unauthenticated subjects). Test asserts Allow for the
    /// public-resource pattern with empty subject attrs.
    #[test]
    fn evaluate_all_matcher_ua_with_empty_subject_attrs_allows_public_resource() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "public".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "public_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa.id),
            operations: HashSet::from(["read".to_string()]),
        });
        // Empty subject attrs — unauthenticated caller — still matches All UA
        let req = AccessRequest::new("read", "job");
        assert_eq!(evaluate(&graph, &req), Decision::Allow);
    }

    // ---- evaluate() UA→PC path tests (REQ-EVAL-004, D16) ----

    /// Allow via UA→PC: OA under the PC matches both resource type and resource
    /// attributes.
    #[test]
    fn evaluate_allows_via_ua_pc_when_oa_matches() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_admins".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_alpha_pc".to_string(),
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
        graph.add_ua(ua.clone());
        graph.add_pc(pc.clone());
        graph.add_oa(oa.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::PolicyClass(pc.id),
            operations: HashSet::from(["read".to_string()]),
        });
        // Alpha member requests alpha job → Allow
        let req = AccessRequest::new("read", "job")
            .subject_attrs(attrs(&[("org_id", &["alpha"])]))
            .resource_attrs(attrs(&[("org_id", &["alpha"])]));
        assert_eq!(evaluate(&graph, &req), Decision::Allow);
    }

    /// REQ-EVAL-004 locked-in review counterexample:
    /// `(org_admins, org_alpha_pc, {read})` with
    /// `alpha_jobs { resource_type: "job", matcher: Matching { org_id ∈ ["alpha"] } }`
    /// under `org_alpha_pc`; requesting a job with `org_id: "beta"` → Deny.
    ///
    /// This locks in Option B (D16): UA→PC keeps the OA-matcher check;
    /// mere existence of OAs under a PC is NOT sufficient.
    ///
    /// # Why the UA uses `AttributeMatcher::All`
    ///
    /// The review counterexample described `org_admins` with
    /// `Matching { org_id ∈ [alpha] }`. Using that matcher here would make the
    /// beta-subject fail at the UA-matching stage rather than at the OA-matcher
    /// check — meaning the test would pass vacuously without exercising the PC
    /// branch at all. Using `All` ensures the subject *does* match the UA and
    /// the deny must come from the OA-matcher check on the PC path, which is the
    /// property being verified.
    #[test]
    fn evaluate_denies_review_counterexample_beta_job_under_alpha_pc() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_alpha_pc".to_string(),
        };
        // OA only admits alpha jobs
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        graph.add_ua(ua.clone());
        graph.add_pc(pc.clone());
        graph.add_oa(oa.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::PolicyClass(pc.id),
            operations: HashSet::from(["read".to_string()]),
        });
        // Resource is a beta-org job — OA matcher (org_id=alpha) does NOT match
        let req = AccessRequest::new("read", "job")
            .subject_attrs(attrs(&[("org_id", &["beta"])]))
            .resource_attrs(attrs(&[("org_id", &["beta"])]));
        assert_eq!(evaluate(&graph, &req), Decision::Deny);
    }

    /// Deny when the PC has no OA for the requested resource type (fail-closed).
    #[test]
    fn evaluate_denies_when_pc_has_no_oa_for_resource_type() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_pc".to_string(),
        };
        // Only a "document" OA under the PC — no "job" OA
        let oa_doc = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "all_docs".to_string(),
            resource_type: "document".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.add_pc(pc.clone());
        graph.add_oa(oa_doc.clone());
        graph.assign_oa_to_pc(oa_doc.id, pc.id);
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::PolicyClass(pc.id),
            operations: HashSet::from(["read".to_string()]),
        });
        // Request for "job" resource type — no OA of that type under the PC
        let req = AccessRequest::new("read", "job");
        assert_eq!(evaluate(&graph, &req), Decision::Deny);
    }

    // ---- evaluate() dangling OA reference test (REQ-EVAL-005) ----

    /// Deny when an association targets a nonexistent OA (dangling reference).
    /// No panic; the association is skipped fail-closed.
    #[test]
    fn evaluate_denies_on_dangling_oa_reference() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "members".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        // Association points to an OA that was never added to the graph
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::from(["read".to_string()]),
        });
        let req = AccessRequest::new("read", "job");
        // Must not panic; dangling reference → Deny
        assert_eq!(evaluate(&graph, &req), Decision::Deny);
    }

    // ---- Decision type tests (REQ-EVAL-001) ----

    #[test]
    fn decision_allow_and_deny_are_not_equal() {
        assert_ne!(Decision::Allow, Decision::Deny);
    }

    #[test]
    fn decision_is_copy() {
        let d = Decision::Allow;
        let d2 = d; // Copy — d still usable
        assert_eq!(d, d2);
    }

    #[test]
    fn decision_debug() {
        assert!(format!("{:?}", Decision::Allow).contains("Allow"));
        assert!(format!("{:?}", Decision::Deny).contains("Deny"));
    }

    // =========================================================
    // Phase 4 — scope() tests (REQ-SCOPE-001…006, REQ-DOC-002)
    // =========================================================

    // ---- Fixture helpers ----

    /// Builds the review-counterexample graph for scope() tests:
    ///
    /// - `ua`: All-matcher (any subject matches)
    /// - `pc`: `org_alpha_pc`
    /// - `oa`: `alpha_jobs` — `resource_type="job"`,
    ///   `Matching { key: "org_id", values: ["alpha"] }`
    /// - OA assigned to PC
    /// - Association: `(ua.id → PC, {"read"})`
    ///
    /// Returns `(graph, ua_id, pc_id, oa_id)`.
    fn scope_pc_graph() -> (PolicyGraph, Uuid, Uuid, Uuid) {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_alpha_pc".to_string(),
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
        graph.add_ua(ua.clone());
        graph.add_pc(pc.clone());
        graph.add_oa(oa.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::PolicyClass(pc.id),
            operations: HashSet::from(["read".to_string()]),
        });
        (graph, ua.id, pc.id, oa.id)
    }

    // ---- ScopeRequest type-shape tests (REQ-SCOPE-001) ----

    /// `ScopeRequest::new` yields empty subject attrs and correct fields.
    #[test]
    fn scope_request_new_has_empty_subject_attrs() {
        let req = ScopeRequest::new("read", "job");
        assert_eq!(req.operation, "read");
        assert_eq!(req.resource_type, "job");
        assert!(req.subject_attrs.is_empty());
    }

    /// Consuming `subject_attrs` setter replaces the default-empty map.
    #[test]
    fn scope_request_subject_attrs_setter_works() {
        let s = attrs(&[("org_id", &["alpha"])]);
        let req = ScopeRequest::new("read", "job").subject_attrs(s.clone());
        assert_eq!(req.subject_attrs, s);
    }

    // ---- ScopeConstraint / AccessScope type-shape tests (REQ-SCOPE-002) ----

    #[test]
    fn scope_constraint_attribute_equality() {
        let c1 = ScopeConstraint::Attribute {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        let c2 = ScopeConstraint::Attribute {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        assert_eq!(c1, c2);
    }

    #[test]
    fn access_scope_variants_not_equal() {
        assert_ne!(AccessScope::Unrestricted, AccessScope::None);
        assert_ne!(AccessScope::Unrestricted, AccessScope::Constrained(vec![]));
    }

    // ---- scope() review counterexample (REQ-SCOPE-003, locked-in) ----

    /// REQ-SCOPE-003 locked-in review counterexample:
    /// `(org_admins, org_alpha_pc, {read})` with
    /// `alpha_jobs { resource_type: "job", matcher: Matching { org_id \u2208 ["alpha"] } }`
    /// assigned to the PC yields
    /// `Constrained([Attribute { key: "org_id", values: ["alpha"] }])`,
    /// **not** `Unrestricted`.
    ///
    /// This locks in D16 (UA→PC is OA expansion, not god-mode): the OA's
    /// `Matching` matcher is preserved in the scope output.
    #[test]
    fn scope_review_counterexample_constrained_not_unrestricted() {
        let (graph, _ua, _pc, _oa) = scope_pc_graph();
        // Subject has org_id=beta but UA is All-matcher — subject matches the UA.
        // The OA has Matching{org_id=["alpha"]} so scope is Constrained.
        let req = ScopeRequest::new("read", "job").subject_attrs(attrs(&[("org_id", &["beta"])]));
        let result = scope(&graph, &req);
        assert_eq!(
            result,
            AccessScope::Constrained(vec![ScopeConstraint::Attribute {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            }])
        );
    }

    // ---- scope() operation-absent and dangling-ref (REQ-SCOPE-003) ----

    /// Associations whose operation set lacks the requested operation
    /// contribute nothing; sole-path result is `None`.
    #[test]
    fn scope_operation_absent_returns_none() {
        let (graph, _ua, _pc, _oa) = scope_pc_graph();
        // Association has "read" but we request "write"
        let req = ScopeRequest::new("write", "job").subject_attrs(attrs(&[("org_id", &["alpha"])]));
        assert_eq!(scope(&graph, &req), AccessScope::None);
    }

    /// A dangling UA→OA reference contributes nothing; sole-path result is `None`.
    #[test]
    fn scope_dangling_oa_reference_returns_none() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "members".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        // Association points to an OA that was never added to the graph
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(Uuid::new_v4()),
            operations: HashSet::from(["read".to_string()]),
        });
        let req = ScopeRequest::new("read", "job");
        assert_eq!(scope(&graph, &req), AccessScope::None);
    }

    // ---- scope() All-matcher short-circuit (REQ-SCOPE-004, D17) ----

    /// `Unrestricted` via an `All`-matcher OA reached through a direct UA→OA
    /// association (public-resources pattern).
    #[test]
    fn scope_unrestricted_via_all_oa_direct_ua_oa() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "public".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "public_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa.id),
            operations: HashSet::from(["read".to_string()]),
        });
        let req = ScopeRequest::new("read", "job");
        assert_eq!(scope(&graph, &req), AccessScope::Unrestricted);
    }

    /// `Unrestricted` via an `All`-matcher OA assigned to a PC reached through
    /// a UA→PC association (platform-admin pattern).
    #[test]
    fn scope_unrestricted_via_all_oa_under_pc() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "platform_admins".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "role".to_string(),
                values: vec!["admin".to_string()],
            },
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_pc".to_string(),
        };
        // All-matcher OA under the PC grants unrestricted job access
        let oa_all = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "all_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.add_pc(pc.clone());
        graph.add_oa(oa_all.clone());
        graph.assign_oa_to_pc(oa_all.id, pc.id);
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::PolicyClass(pc.id),
            operations: HashSet::from(["read".to_string()]),
        });
        let req = ScopeRequest::new("read", "job").subject_attrs(attrs(&[("role", &["admin"])]));
        assert_eq!(scope(&graph, &req), AccessScope::Unrestricted);
    }

    /// A mix of one `All`-matcher OA and several `Matching` OAs still returns
    /// `Unrestricted`, not `Constrained`.
    #[test]
    fn scope_mixed_all_and_matching_oa_returns_unrestricted() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa_alpha = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let oa_all = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "all_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa_alpha.clone());
        graph.add_oa(oa_all.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa_alpha.id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa_all.id),
            operations: HashSet::from(["read".to_string()]),
        });
        let req = ScopeRequest::new("read", "job");
        assert_eq!(scope(&graph, &req), AccessScope::Unrestricted);
    }

    // ---- scope() constraint merging (REQ-SCOPE-005) ----

    /// Two OAs with `{ org_id \u2208 [alpha] }` and `{ org_id \u2208 [beta] }` merge into
    /// one constraint `Attribute { key: "org_id", values: ["alpha", "beta"] }`.
    #[test]
    fn scope_same_key_values_merged_into_one_constraint() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_members".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa_alpha = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let oa_beta = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "beta_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["beta".to_string()],
            },
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa_alpha.clone());
        graph.add_oa(oa_beta.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa_alpha.id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa_beta.id),
            operations: HashSet::from(["read".to_string()]),
        });
        let req = ScopeRequest::new("read", "job");
        let result = scope(&graph, &req);
        // Extract the single constraint and verify values contain both orgs
        if let AccessScope::Constrained(constraints) = result {
            assert_eq!(constraints.len(), 1);
            let ScopeConstraint::Attribute { key, values } = &constraints[0];
            assert_eq!(key, "org_id");
            assert_eq!(values.len(), 2);
            // Assert first-seen order: oa_alpha association was added first.
            assert_eq!(values[0], "alpha", "first-seen value must be first");
            assert_eq!(values[1], "beta");
        } else {
            panic!("Expected Constrained, got {:?}", result);
        }
    }

    /// Duplicate values across OAs are deduplicated in the merged constraint.
    #[test]
    fn scope_duplicate_values_deduped() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "members".to_string(),
            matcher: AttributeMatcher::All,
        };
        // Both OAs include "alpha"; second also includes "beta"
        let oa1 = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "oa1".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let oa2 = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "oa2".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string(), "beta".to_string()],
            },
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa1.clone());
        graph.add_oa(oa2.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa1.id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa2.id),
            operations: HashSet::from(["read".to_string()]),
        });
        let req = ScopeRequest::new("read", "job");
        let result = scope(&graph, &req);
        if let AccessScope::Constrained(constraints) = result {
            assert_eq!(constraints.len(), 1);
            let ScopeConstraint::Attribute { key, values } = &constraints[0];
            assert_eq!(key, "org_id");
            assert_eq!(values.len(), 2, "alpha should be deduplicated");
            // Assert first-seen order: oa1 (alpha-only) was added first,
            // then oa2 (alpha, beta) — alpha seen first, beta seen second.
            assert_eq!(values[0], "alpha", "first-seen value must be first");
            assert_eq!(values[1], "beta");
        } else {
            panic!("Expected Constrained, got {:?}", result);
        }
    }

    /// Two OAs with distinct keys produce two separate OR-combined constraints.
    #[test]
    fn scope_distinct_keys_produce_two_constraints() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "members".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa_org = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "org_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let oa_team = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "team_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "team_id".to_string(),
                values: vec!["engineering".to_string()],
            },
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa_org.clone());
        graph.add_oa(oa_team.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa_org.id),
            operations: HashSet::from(["read".to_string()]),
        });
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa_team.id),
            operations: HashSet::from(["read".to_string()]),
        });
        let req = ScopeRequest::new("read", "job");
        let result = scope(&graph, &req);
        if let AccessScope::Constrained(constraints) = result {
            assert_eq!(
                constraints.len(),
                2,
                "distinct keys produce two constraints"
            );
            // Assert first-seen key order: oa_org association was added first.
            let keys: Vec<&str> = constraints
                .iter()
                .map(|c| match c {
                    ScopeConstraint::Attribute { key, .. } => key.as_str(),
                })
                .collect();
            assert_eq!(keys[0], "org_id", "first-seen key must be first");
            assert_eq!(keys[1], "team_id");
        } else {
            panic!("Expected Constrained, got {:?}", result);
        }
    }

    /// Specific-object pattern: an OA with `{ key: "id", values: [resource_id] }`
    /// yields `Constrained([Attribute { key: "id", values: [resource_id] }])`.
    #[test]
    fn scope_specific_object_id_constraint() {
        let mut graph = PolicyGraph::new();
        let resource_id = Uuid::new_v4().to_string();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "specific_user".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "specific_job".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "id".to_string(),
                values: vec![resource_id.clone()],
            },
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa.id),
            operations: HashSet::from(["read".to_string()]),
        });
        let req = ScopeRequest::new("read", "job");
        assert_eq!(
            scope(&graph, &req),
            AccessScope::Constrained(vec![ScopeConstraint::Attribute {
                key: "id".to_string(),
                values: vec![resource_id],
            }])
        );
    }

    // ---- scope() None cases (REQ-SCOPE-006) ----

    /// `None` when no UA matches the subject attributes.
    #[test]
    fn scope_none_when_no_ua_matches() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "alpha_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "alpha_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa.id),
            operations: HashSet::from(["read".to_string()]),
        });
        // Subject is in org "gamma" — no UA matches
        let req = ScopeRequest::new("read", "job").subject_attrs(attrs(&[("org_id", &["gamma"])]));
        assert_eq!(scope(&graph, &req), AccessScope::None);
    }

    /// `None` when the requested operation is not in any association.
    #[test]
    fn scope_none_when_operation_not_granted() {
        let (graph, _ua, _pc, _oa) = scope_pc_graph();
        // Graph only has "read"; request for "delete"
        let req = ScopeRequest::new("delete", "job");
        assert_eq!(scope(&graph, &req), AccessScope::None);
    }

    /// `None` when the resource type has no matching OAs (wrong type requested).
    #[test]
    fn scope_none_when_resource_type_has_no_oas() {
        let (graph, _ua, _pc, _oa) = scope_pc_graph();
        // Graph has OAs for "job" only; request for "document"
        let req = ScopeRequest::new("read", "document");
        assert_eq!(scope(&graph, &req), AccessScope::None);
    }

    /// `None` when a UA→PC association exists but the PC has no OAs of the
    /// requested resource type.
    #[test]
    fn scope_none_when_pc_has_no_oas_of_resource_type() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_pc".to_string(),
        };
        // Only a "document" OA under the PC — no "job" OA
        let oa_doc = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "all_docs".to_string(),
            resource_type: "document".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.add_pc(pc.clone());
        graph.add_oa(oa_doc.clone());
        graph.assign_oa_to_pc(oa_doc.id, pc.id);
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::PolicyClass(pc.id),
            operations: HashSet::from(["read".to_string()]),
        });
        // Request for "job" resource type — PC only has "document" OAs
        let req = ScopeRequest::new("read", "job");
        assert_eq!(scope(&graph, &req), AccessScope::None);
    }

    // ---- AccessScope / ScopeConstraint derive tests (REQ-SCOPE-002) ----

    #[test]
    fn access_scope_debug() {
        assert!(format!("{:?}", AccessScope::Unrestricted).contains("Unrestricted"));
        assert!(format!("{:?}", AccessScope::None).contains("None"));
    }

    #[test]
    fn access_scope_clone() {
        let scope_val = AccessScope::Constrained(vec![ScopeConstraint::Attribute {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        }]);
        let cloned = scope_val.clone();
        assert_eq!(scope_val, cloned);
    }

    #[test]
    fn scope_constraint_debug() {
        let c = ScopeConstraint::Attribute {
            key: "org_id".to_string(),
            values: vec!["alpha".to_string()],
        };
        assert!(format!("{:?}", c).contains("Attribute"));
        assert!(format!("{:?}", c).contains("org_id"));
    }
}

// ---------------------------------------------------------------------------
// REQ-INV-001 — evaluate()/scope() soundness invariant tests
// ---------------------------------------------------------------------------

/// Canonical pattern fixtures and the soundness invariant: for any
/// `(subject, operation, resource_type)` triple, `scope_admits(scope(...), r)`
/// iff `evaluate(..., r) == Allow` for every resource `r`.
#[cfg(test)]
mod invariant_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;

    // ------------------------------------------------------------------
    // Shared helpers
    // ------------------------------------------------------------------

    /// Constructs a multi-valued attribute map from key/value-slice pairs.
    fn attrs(pairs: &[(&str, &[&str])]) -> HashMap<String, HashSet<String>> {
        pairs
            .iter()
            .map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect()))
            .collect()
    }

    /// Returns `true` when `resource_attrs` is admitted by `s`.
    ///
    /// - [`AccessScope::Unrestricted`] → always `true`.
    /// - [`AccessScope::None`] → always `false`.
    /// - [`AccessScope::Constrained`] → `true` when *any* constraint's
    ///   `values` share at least one element with the resource's value-set for
    ///   `key` (D18 non-empty intersection semantics, mirroring
    ///   [`AttributeMatcher::matches`]).
    fn scope_admits(s: &AccessScope, resource_attrs: &HashMap<String, HashSet<String>>) -> bool {
        match s {
            AccessScope::Unrestricted => true,
            AccessScope::None => false,
            AccessScope::Constrained(constraints) => constraints.iter().any(|c| {
                let ScopeConstraint::Attribute { key, values } = c;
                resource_attrs
                    .get(key)
                    .is_some_and(|vs| vs.iter().any(|v| values.contains(v)))
            }),
        }
    }

    /// Asserts the soundness invariant for every resource in `resources`:
    ///
    /// `scope_admits(scope(graph, sreq), r)` ⟺ `evaluate(graph, areq) == Allow`
    fn check_invariant(
        graph: &PolicyGraph,
        subject_attrs: &HashMap<String, HashSet<String>>,
        operation: &str,
        resource_type: &str,
        resources: &[HashMap<String, HashSet<String>>],
    ) {
        let sreq = ScopeRequest::new(operation, resource_type).subject_attrs(subject_attrs.clone());
        let s = scope(graph, &sreq);

        for resource in resources {
            let admitted = scope_admits(&s, resource);
            let areq = AccessRequest::new(operation, resource_type)
                .subject_attrs(subject_attrs.clone())
                .resource_attrs(resource.clone());
            let allowed = evaluate(graph, &areq) == Decision::Allow;
            assert_eq!(
                admitted,
                allowed,
                "Invariant violated for resource {:?}: \
                 scope_admits={admitted}, evaluate=={}",
                resource,
                if allowed { "Allow" } else { "Deny" }
            );
        }
    }

    // ------------------------------------------------------------------
    // Pattern 1: Platform admin — All OA under platform PC → Unrestricted
    // ------------------------------------------------------------------

    /// Builds a platform-admin graph: `All`-matcher UA associated with a
    /// platform PC that owns an `All`-matcher OA for "job" resources.
    fn platform_admin_graph() -> (PolicyGraph, HashMap<String, HashSet<String>>) {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "platform_admins".to_string(),
            matcher: AttributeMatcher::All,
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "platform_pc".to_string(),
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "all_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.add_pc(pc.clone());
        graph.add_oa(oa.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::PolicyClass(pc.id),
            operations: HashSet::from(["read".to_string()]),
        });
        // Platform admins match `All` — empty subject attrs suffice.
        (graph, attrs(&[]))
    }

    /// Pattern 1: platform admin via `All` OA under platform PC.
    ///
    /// Scope → `Unrestricted`; every job resource is admitted and
    /// `evaluate` returns `Allow` — invariant holds.
    #[test]
    fn invariant_platform_admin() {
        let (graph, subject) = platform_admin_graph();

        let sreq = ScopeRequest::new("read", "job").subject_attrs(subject.clone());
        assert_eq!(scope(&graph, &sreq), AccessScope::Unrestricted);

        let resources = [
            attrs(&[("org_id", &["alpha"])]),
            attrs(&[("org_id", &["beta"])]),
            attrs(&[("org_id", &["alpha", "beta"])]),
            attrs(&[]),
        ];
        check_invariant(&graph, &subject, "read", "job", &resources);
    }

    // ------------------------------------------------------------------
    // Pattern 2: Org-scoped admin — UA→PC, Matching OA → Constrained
    // ------------------------------------------------------------------

    /// Builds an org-scoped-admin graph: a `role=admin`-matcher UA associated
    /// with an org PC that owns an `org_id=alpha`-matcher OA for "job".
    fn org_scoped_admin_graph() -> (PolicyGraph, HashMap<String, HashSet<String>>) {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "org_alpha_admins".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "role".to_string(),
                values: vec!["admin".to_string()],
            },
        };
        let pc = PolicyClass {
            id: Uuid::new_v4(),
            name: "org_alpha_pc".to_string(),
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
        graph.add_ua(ua.clone());
        graph.add_pc(pc.clone());
        graph.add_oa(oa.clone());
        graph.assign_oa_to_pc(oa.id, pc.id);
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::PolicyClass(pc.id),
            operations: HashSet::from(["read".to_string()]),
        });
        let subject = attrs(&[("role", &["admin"])]);
        (graph, subject)
    }

    /// Pattern 2: org-scoped admin via UA→PC expansion (locked-in counterexample
    /// from REQ-EVAL-004 / REQ-SCOPE-003).
    ///
    /// Scope → `Constrained([org_id ∈ ["alpha"]])` (not `Unrestricted`!);
    /// alpha jobs admitted, beta jobs denied — both sides agree.
    #[test]
    fn invariant_org_scoped_admin() {
        let (graph, subject) = org_scoped_admin_graph();

        // Locked-in counterexample: UA→PC must NOT return Unrestricted
        let sreq = ScopeRequest::new("read", "job").subject_attrs(subject.clone());
        assert_eq!(
            scope(&graph, &sreq),
            AccessScope::Constrained(vec![ScopeConstraint::Attribute {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            }])
        );

        let resources = [
            attrs(&[("org_id", &["alpha"])]),         // in-scope
            attrs(&[("org_id", &["alpha", "beta"])]), // in-scope (D18: alpha present)
            attrs(&[("org_id", &["beta"])]),          // out-of-scope
            attrs(&[("org_id", &["gamma"])]),         // out-of-scope
            attrs(&[]),                               // out-of-scope (no org_id)
        ];
        check_invariant(&graph, &subject, "read", "job", &resources);
    }

    // ------------------------------------------------------------------
    // Pattern 3: Org member — direct UA→OA → Constrained
    // ------------------------------------------------------------------

    /// Builds an org-member graph: an `org_id=alpha`-matcher UA directly
    /// associated with an `org_id=alpha`-matcher OA for "job" resources.
    fn org_member_graph() -> (PolicyGraph, HashMap<String, HashSet<String>>) {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "alpha_members".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            },
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
        graph.add_ua(ua.clone());
        graph.add_oa(oa.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa.id),
            operations: HashSet::from(["read".to_string()]),
        });
        let subject = attrs(&[("org_id", &["alpha"])]);
        (graph, subject)
    }

    /// Pattern 3: org member via direct UA→OA association.
    ///
    /// Scope → `Constrained([org_id ∈ ["alpha"]])`;
    /// alpha jobs admitted, beta jobs denied — both sides agree.
    #[test]
    fn invariant_org_member() {
        let (graph, subject) = org_member_graph();

        let sreq = ScopeRequest::new("read", "job").subject_attrs(subject.clone());
        assert_eq!(
            scope(&graph, &sreq),
            AccessScope::Constrained(vec![ScopeConstraint::Attribute {
                key: "org_id".to_string(),
                values: vec!["alpha".to_string()],
            }])
        );

        let resources = [
            attrs(&[("org_id", &["alpha"])]),
            attrs(&[("org_id", &["alpha", "beta"])]),
            attrs(&[("org_id", &["beta"])]),
            attrs(&[]),
        ];
        check_invariant(&graph, &subject, "read", "job", &resources);
    }

    // ------------------------------------------------------------------
    // Pattern 4: Specific object — key:"id" OA matcher → Constrained
    // ------------------------------------------------------------------

    /// Pattern 4: specific-object access where the OA carries a
    /// `key: "id"` matcher scoped to a single resource ID.
    ///
    /// Scope → `Constrained([id ∈ [target_id]])`;
    /// the target job is admitted, all other jobs denied — both sides agree.
    #[test]
    fn invariant_specific_object() {
        let target_id = "job-abc-123";
        let other_id = "job-xyz-456";

        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "specific_user".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "user_id".to_string(),
                values: vec!["user-123".to_string()],
            },
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "specific_job".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::Matching {
                key: "id".to_string(),
                values: vec![target_id.to_string()],
            },
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa.id),
            operations: HashSet::from(["read".to_string()]),
        });

        let subject = attrs(&[("user_id", &["user-123"])]);

        let sreq = ScopeRequest::new("read", "job").subject_attrs(subject.clone());
        assert_eq!(
            scope(&graph, &sreq),
            AccessScope::Constrained(vec![ScopeConstraint::Attribute {
                key: "id".to_string(),
                values: vec![target_id.to_string()],
            }])
        );

        let resources = [
            attrs(&[("id", &[target_id])]), // in-scope: the specific job
            attrs(&[("id", &[other_id])]),  // out-of-scope: different job
            attrs(&[]),                     // out-of-scope: no id key
        ];
        check_invariant(&graph, &subject, "read", "job", &resources);
    }

    // ------------------------------------------------------------------
    // Pattern 5: Public resource — All UA → All OA → Unrestricted
    // ------------------------------------------------------------------

    /// Pattern 5: public-resource access — `All`-matcher UA directly
    /// associated with an `All`-matcher OA.
    ///
    /// Scope → `Unrestricted`; every job is admitted and evaluates to `Allow`.
    /// Empty subject attributes match the `All` UA (the unauthenticated sharp
    /// edge documented on [`AttributeMatcher::All`]).
    #[test]
    fn invariant_public_resource() {
        let mut graph = PolicyGraph::new();
        let ua = UserAttribute {
            id: Uuid::new_v4(),
            name: "all_users".to_string(),
            matcher: AttributeMatcher::All,
        };
        let oa = ObjectAttribute {
            id: Uuid::new_v4(),
            name: "public_jobs".to_string(),
            resource_type: "job".to_string(),
            matcher: AttributeMatcher::All,
        };
        graph.add_ua(ua.clone());
        graph.add_oa(oa.clone());
        graph.add_association(Association {
            ua_id: ua.id,
            target: AssociationTarget::ObjectAttribute(oa.id),
            operations: HashSet::from(["read".to_string()]),
        });

        // Empty subject attrs — matches `All` (public / unauthenticated callers).
        let subject = attrs(&[]);

        let sreq = ScopeRequest::new("read", "job").subject_attrs(subject.clone());
        assert_eq!(scope(&graph, &sreq), AccessScope::Unrestricted);

        let resources = [
            attrs(&[("org_id", &["alpha"])]),
            attrs(&[("org_id", &["beta"])]),
            attrs(&[]),
        ];
        check_invariant(&graph, &subject, "read", "job", &resources);
    }
}

pub mod aggregate;
pub mod time_travel;
