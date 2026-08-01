#![deny(unsafe_code)]
//! Authenticated local directory-record components.
//!
//! The TCP API is a prototype control-plane interface. It is not a public
//! directory service or a consensus implementation.

pub mod api;
pub mod signed_record;
pub mod store;
