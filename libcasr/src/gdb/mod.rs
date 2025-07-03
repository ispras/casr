//! Gdb module implements `ParseStacktrace`, `Exception` and `Severity` traits for Gdb output.
use gdb_command::stacktrace::StacktraceExt;
use regex::Regex;

use super::{
    error::Result,
    stacktrace::{ParseStacktrace, Stacktrace, StacktraceEntry},
};

#[cfg(feature = "exploitable")]
pub mod exploitable;
#[cfg(feature = "exploitable")]
pub mod report;

/// Structure provides an interface for processing the stack trace.
pub struct GdbStacktrace;

impl ParseStacktrace for GdbStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let frame = Regex::new(r"^ *#[0-9]+").unwrap();
        Ok(stream
            .split('\n')
            .filter(|x| frame.is_match(x))
            .map(|x| x.to_string())
            .collect())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        Ok(StacktraceEntry::new(entry)?)
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        Ok(Stacktrace::from_gdb(entries.join("\n"))?)
    }
}
