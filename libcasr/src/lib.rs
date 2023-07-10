//! # LibCASR
//! LibCASR provides API for parsing stacktraces, collecting crash reports,
//! triaging crashes (deduplication and clustering), and estimating severity of
//! crashes.
//!
//! It can analyze crashes from different sources:
//!
//! * AddressSanitizer
//! * Gdb output
//!
//! and program languages:
//!
//! * C/C++
//! * Rust
//! * Go
//! * Python
//! * Java
//!
//! It could be built with `exploitable` feature for severity estimation crashes
//! collected from gdb. To save crash reports as json use `serde` feature.

pub mod asan;
pub mod constants;
pub mod cpp;
pub mod error;
pub mod exception;
pub mod execution_class;
pub mod gdb;
pub mod go;
pub mod java;
pub mod python;
pub mod report;
pub mod rust;
pub mod severity;
pub mod stacktrace;
