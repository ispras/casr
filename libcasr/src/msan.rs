//! Msan module implements `ParseStacktrace` and `Severity` traits for MemorySanitizer
//! reports.
use regex::Regex;

use crate::error::*;
use crate::asan::AsanStacktrace;
use crate::execution_class::ExecutionClass;
use crate::severity::Severity;
use crate::stacktrace::ParseStacktrace;
use crate::stacktrace::*;

/// Structure provides an interface for processing the stack trace.
pub struct MsanStacktrace;

impl ParseStacktrace for MsanStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        return AsanStacktrace::extract_stacktrace(stream)
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        return AsanStacktrace::parse_stacktrace_entry(entry)
    }
}

// Information about sanitizer crash state.
pub struct MsanContext(pub Vec<String>);

impl Severity for MsanContext {
    fn severity(&self) -> Result<ExecutionClass> {
        let msan_report = &self.0;
        if msan_report.is_empty() {
            return Err(Error::Casr(
                "Cannot estimate severity: Msan is empty.".to_string(),
            ));
        }
        let summary = Regex::new(r"SUMMARY: *(MemorySanitizer): ([A-Za-z_\-\(\)]+)").unwrap();
        let Some(caps) = msan_report.iter().find_map(|s| summary.captures(s)) else {
            return Err(Error::Casr(
                "Cannot find SUMMARY in Sanitizer report".to_string(),
            ));
        };
        return ExecutionClass::find(caps.get(2).unwrap().as_str());
    }
}