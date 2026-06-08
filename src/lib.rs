//! Core library for Intent.
//!
//! Intent is a declarative security policy compiler for Linux. The library
//! owns the schema, compiler backends, audit-log analysis, and diagnostics used
//! by the `intent` CLI.

pub mod audit;
pub mod compiler;
pub mod config;
pub mod diagnostics;
pub mod ir;
pub mod schema;
