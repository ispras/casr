//! # LibCASR
//! LibCASR provides API for parsing stacktraces, collecting crash reports,
//! triaging crashes (deduplication and clustering), and estimating severity of
//! crashes.
//!
//! It can analyze crashes from different sources:
//!
//! * AddressSanitizer
//! * MemorySanitizer
//! * UndefinedBehaviorSanitizer
//! * Gdb output
//!
//! and program languages:
//!
//! * C/C++
//! * C#
//! * Go
//! * Java
//! * JavaScript
//! * Lua
//! * Python
//! * Rust
//!
//! It could be built with `exploitable` feature for severity estimation crashes
//! collected from gdb. To save crash reports as json (.casrep/.sarif) use `serde` feature.

pub mod asan;
pub mod cluster;
pub mod constants;
pub mod cpp;
pub mod csharp;
pub mod error;
pub mod exception;
pub mod execution_class;
pub mod gdb;
pub mod go;
pub mod java;
pub mod js;
pub mod lua;
pub mod msan;
pub mod python;
pub mod report;
pub mod rust;
#[cfg(feature = "serde")]
pub mod sarif;
pub mod severity;
pub mod stacktrace;
pub mod ubsan;
