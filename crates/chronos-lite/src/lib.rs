#![deny(unsafe_code)]
//! Parse-only components and local algorithm tests for the lite prototype.
//!
//! This crate does not expose a runnable client or network transport.

pub mod config;

#[cfg(test)]
mod dpf_store;
#[cfg(test)]
mod secure_udp;
