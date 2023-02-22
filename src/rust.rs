use crate::exception::Exception;
use crate::execution_class::ExecutionClass;

use regex::Regex;

/// Structure provides an interface for parsing rust panic message.
pub struct RustPanic;

impl Exception for RustPanic {
    fn parse_exception(stderr: &str) -> Option<ExecutionClass> {
        let stderr_list: Vec<String> = stderr
            .split('\n')
            .map(|l| l.trim_end().to_string())
            .collect();
        let rexception = Regex::new(r"thread '.+?' panicked at '(.+)?'").unwrap();
        if let Some(pos) = stderr_list
            .iter()
            .position(|line| rexception.is_match(line))
        {
            let message = rexception
                .captures(&stderr_list[pos])
                .unwrap()
                .get(1)
                .unwrap()
                .as_str();
            Some(ExecutionClass::new((
                "NOT_EXPLOITABLE",
                "RustPanic",
                message,
                "",
            )))
        } else {
            None
        }
    }
}
