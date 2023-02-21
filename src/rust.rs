use crate::execution_class::ExecutionClass;
use crate::util::Exception;

use regex::Regex;

pub struct RustPanic;

impl Exception for RustPanic {
    fn parse_exception(stderr_list: &[String]) -> Option<ExecutionClass> {
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
