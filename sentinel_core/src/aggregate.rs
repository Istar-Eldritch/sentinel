//! # Policy Aggregate
//!
//! Event-sourced persistence layer for the policy graph, using the
//! [epoch](https://github.com/Istar-Eldritch/epoch) CQRS/event-sourcing framework.
//!
//! This module defines:
//! - [`PolicyEvent`] — events emitted by policy mutations
//! - [`PolicyCommand`] — commands that mutate the policy graph
//! - [`PolicyState`] — the persisted aggregate state wrapping [`PolicyGraph`](crate::PolicyGraph)
//! - [`PolicyAggregate`] — the event-sourced aggregate handling commands and applying events
//! - [`PolicyActor`] — credentials carrying the actor ID for audit trails

// Validate epoch dependency wiring — these imports will be used in later phases.
#[allow(unused_imports)]
use epoch_core::prelude::*;
#[allow(unused_imports)]
use epoch_derive::EventData;
