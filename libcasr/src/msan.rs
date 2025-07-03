//! Asan module implements `ParseStacktrace`, `Exception`, `Severity` and `ReportExtracter` traits
//! for MemorySanitizer reports.
use regex::Regex;

use crate::{
    asan::SanCrash,
    error::{Error, Result},
    execution_class::ExecutionClass,
    report::ReportExtractor,
    stacktrace::{CrashLine, Stacktrace},
};

/// Structure provides an interface for save parsing MemorySanitizer crash.
#[derive(Clone, Debug)]
pub struct MsanCrash {
    // NOTE: There's no structure inheritance in Rust :(
    san: SanCrash,
    stream: String,
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

        let report: Vec<String> = stream.split('\n').map(|l| l.trim().to_string()).collect();
        let start = Regex::new(r"==\d+==\s*WARNING: MemorySanitizer:").unwrap();
        let Some(start) = report.iter().position(|l| start.is_match(l)) else {
            return Ok(None::<Self>);
        };
        let report = &report[start..];
        if report.is_empty() {
            return Ok(None::<Self>);
        }

        Ok(Some(Self {
            san: SanCrash::new(report.join("\n")),
            stream: stream.to_string(),
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
        &self.stream
    }
    fn report(&self) -> Vec<String> {
        self.san.report()
    }
    fn execution_class(&self) -> Result<ExecutionClass> {
        self.san.execution_class()
    }
}
