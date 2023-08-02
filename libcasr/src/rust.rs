//! Rust module implements `Exception` traits for Rust panic messages.
use crate::exception::Exception;
use crate::execution_class::ExecutionClass;

use regex::Regex;

/// Structure provides an interface for parsing rust panic message.
pub struct RustPanic;

impl Exception for RustPanic {
    fn parse_exception(stderr: &str) -> Option<ExecutionClass> {
        let rexception = Regex::new(r"thread '.+?' panicked at (?:'(.+)?'|.+?:\n(.+))").unwrap();
        let Some(captures) = rexception
            .captures(stderr) else {
            return None;
        };
        let message = if let Some(message) = captures.get(1) {
            message.as_str()
        } else {
            captures.get(2).unwrap().as_str()
        };
        Some(ExecutionClass::new((
            "NOT_EXPLOITABLE",
            "RustPanic",
            message,
            "",
        )))
    }
}
