//! Asan module implements `ParseStacktrace`, `Exception`, `Severity` and `ReportExtracter` traits
//! for MemorySanitizer reports.
use crate::{
    asan::SanCrash,
    error::{Error, Result},
    execution_class::ExecutionClass,
    report::ReportExtractor,
    stacktrace::{CrashLine, Stacktrace},
};

use regex::Regex;

/// Structure provides an interface for save parsing MemorySanitizer crash.
#[derive(Clone, Debug)]
pub struct MsanCrash {
    // NOTE: There's no structure inheritance in Rust :(
    san: SanCrash,
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

        let stream: Vec<String> = stream.split('\n').map(|l| l.trim().to_string()).collect();
        let start = Regex::new(r"==\d+==\s*WARNING: MemorySanitizer:").unwrap();
        let Some(start) = stream.iter().position(|l| start.is_match(l)) else {
            return Ok(None::<Self>);
        };
        let report = &stream[start..];
        if report.is_empty() {
            return Ok(None::<Self>);
        }

        Ok(Some(Self {
            san: SanCrash::new(report.join("\n")),
        }))
    }
}

impl ReportExtractor for MsanCrash {
    fn extract_stacktrace(&mut self) -> Result<Vec<String>> {
        self.san.extract_stacktrace()
    }
    fn parse_stacktrace(&mut self) -> Result<Stacktrace> {
        self.san.parse_stacktrace()
    }
    fn crash_line(&mut self) -> Result<CrashLine> {
        self.san.crash_line()
    }
    fn stream(&self) -> &str {
        self.san.stream()
    }
    fn report(&self) -> Vec<String> {
        self.san.report()
    }
    fn execution_class(&self) -> Option<ExecutionClass> {
        self.san.execution_class()
    }
}
