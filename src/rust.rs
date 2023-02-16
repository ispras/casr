use crate::execution_class::ExecutionClass;
use crate::util::Exception;

use regex::Regex;

pub struct RustAnalysis;

impl Exception for RustAnalysis {
    /// Extract rust panic message from stderr                 
    ///                                                                              
    /// # Arguments                                                                  
    ///                                                                              
    /// * `stderr_list` - lines of stderr                                            
    ///                                                                              
    /// # Return value                                                               
    ///                                                                              
    /// Exception info as a `ExecutionClass` struct                                  
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
