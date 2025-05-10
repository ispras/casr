//! Asan module implements `ParseStacktrace`, `Exception`, `Severity` and `ReportExtracter` traits
//! for MemorySanitizer reports.
use regex::Regex;

use crate::asan::SanCrash;
use crate::error::*;
use crate::execution_class::ExecutionClass;
use crate::report::ReportExtractor;
use crate::stacktrace::*;

/// Structure provides an interface for save parsing MemorySanitizer crash.
#[derive(Clone, Debug)]
pub struct MsanCrash {
    // NOTE: There's no structure inheritance in Rust :(
    san_crash: SanCrash,
}

impl MsanCrash {
    /// Create new `MsanCrash` instance from stream
    pub fn new(stream: &str) -> Result<Option<Self>> {
        if stream.contains("Cannot set personality") {
            return Err(Error::Casr(
                "Cannot set personality (if you are running docker, allow personality syscall in your seccomp profile)".to_string()
            ));
        }

        if !stream.contains("WARNING: MemorySanitizer:") {
            return Ok(None::<Self>);
        }

        let lines: Vec<String> = stream
            .split('\n')
            .map(|l| l.trim_end().to_string())
            .collect();
        let start = Regex::new(r"==\d+==\s*WARNING: MemorySanitizer:").unwrap();
        let Some(start) = lines.iter().position(|line| start.is_match(line)) else {
            return Ok(None::<Self>);
        };

        let end = lines.iter().rposition(|s| !s.is_empty()).unwrap() + 1;
        let slice = &lines[start..end];

        if slice.is_empty() {
            return Ok(None::<Self>);
        }

        Ok(Some(MsanCrash {
            san_crash: SanCrash::new(slice.to_vec()),
        }))
    }
}

impl ReportExtractor for MsanCrash {
    fn extract_stacktrace(&mut self) -> Result<Vec<String>> {
        self.san_crash.extract_stacktrace()
    }
    fn parse_stacktrace(&mut self) -> Result<Stacktrace> {
        self.san_crash.parse_stacktrace()
    }
    fn report(&self) -> Vec<String> {
        self.san_crash.report()
    }
    fn execution_class(&self) -> Option<ExecutionClass> {
        self.san_crash.execution_class()
    }
    fn crash_line(&mut self) -> Result<CrashLine> {
        self.san_crash.crash_line()
    }
}
