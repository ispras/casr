//! Cpp module implements `Exception` trait for C++ exception messages.
use crate::exception::Exception;
use crate::execution_class::ExecutionClass;

use regex::Regex;

/// Structure provides an interface for parsing C++ exception message.
pub struct CppException;

impl Exception for CppException {
    fn parse_exception(stderr: &str) -> Option<ExecutionClass> {
        let stderr_list: Vec<String> = stderr
            .split('\n')
            .map(|l| l.trim_end().to_string())
            .collect();
        let rexception =
            Regex::new(r"terminate called after throwing an instance of (.+)").unwrap();
        let Some(pos) = stderr_list
            .iter()
            .position(|line| rexception.is_match(line))
        else {
            return None;
        };
        let instance = rexception
            .captures(&stderr_list[pos])
            .unwrap()
            .get(1)
            .unwrap()
            .as_str()
            .trim_start_matches('\'')
            .trim_end_matches('\'');
        let message = if let Some(element) = stderr_list.get(pos + 1) {
            let rwhat = Regex::new(r"what\(\): +(.+)").unwrap();
            if let Some(cap) = rwhat.captures(element) {
                cap.get(1).unwrap().as_str().trim()
            } else {
                ""
            }
        } else {
            ""
        };
        Some(ExecutionClass::new((
            "NOT_EXPLOITABLE",
            instance,
            message,
            "",
        )))
    }
}
