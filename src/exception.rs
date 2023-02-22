use crate::execution_class::ExecutionClass;

pub trait Exception {
    /// Extract exception info and return it as a `ExecutionClass` struct
    fn parse_exception(stream: &str) -> Option<ExecutionClass>;
}
