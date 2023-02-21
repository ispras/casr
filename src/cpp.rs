use crate::execution_class::ExecutionClass;
use crate::util::Exception;

use regex::Regex;

pub struct CppException;

impl Exception for CppException {
    fn parse_exception(stderr_list: &[String]) -> Option<ExecutionClass> {
        let rexception =
            Regex::new(r"terminate called after throwing an instance of (.+)").unwrap();
        if let Some(pos) = stderr_list
            .iter()
            .position(|line| rexception.is_match(line))
        {
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
        } else {
            None
        }
    }
}
