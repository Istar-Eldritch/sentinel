//! # Sentinel
//!
//! NGAC-inspired policy enforcement library for Rust.
//!
//! Sentinel provides a centralized Policy Enforcement Point (PEP) backed by
//! an attribute-matching policy graph. It is domain-agnostic — applications
//! define their own resource types, operations, and attribute vocabularies.
//!
//! ## Crate Structure
//!
//! - **`sentinel_core`**: Pure graph model, traits, PEP evaluation, scope resolution
//! - **`sentinel_derive`**: Proc macros for policy enforcement annotations
//! - **`sentinel`** (this crate): Facade with feature-gated re-exports

#![deny(missing_docs)]
#![allow(unused_imports)]

/// Core graph model, traits, and policy evaluation.
pub mod core {
    pub use sentinel_core::*;
}

/// Proc macros for policy enforcement annotations.
#[cfg(feature = "derive")]
pub mod derive {
    pub use sentinel_derive::*;
}

pub mod prelude {
    //! Re-exports of the most commonly used sentinel types and traits.
    pub use sentinel_core::*;

    #[cfg(feature = "derive")]
    pub use super::derive::*;
}
