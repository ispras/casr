use crate::stacktrace::ProcessStacktrace;
use crate::util::Exception;

use crate::execution_class::ExecutionClass;
use anyhow::{bail, Result};
use gdb_command::stacktrace::*;
use regex::Regex;

pub struct PythonAnalysis;

impl ProcessStacktrace for PythonAnalysis {
    /// Detect stack trace in python report                      
    ///                                                                          
    /// # Arguments                                                              
    ///                                                                          
    /// * `stream` - python report                                            
    ///                                                                          
    /// # Return value                                                           
    ///                                                                          
    /// Stack trace as vector of strings                                         
    fn detect_stacktrace(stream: &str) -> Result<Vec<String>> {
        // Get stack trace from python report.
        let stacktrace = stream
            .split('\n')
            .map(|l| l.to_string())
            .collect::<Vec<String>>();
        let first = stacktrace
            .iter()
            .position(|line| line.starts_with("Traceback "));
        if first.is_none() {
            bail!("Couldn't find traceback in python report");
        }

        // Stack trace is splitted by empty line.
        let first = first.unwrap();
        let last = stacktrace.iter().skip(first).rposition(|s| !s.is_empty());
        if last.is_none() {
            bail!("Couldn't find traceback end in python report");
        }
        let last = last.unwrap();

        let re = Regex::new(
            r#"(File ".+", line [\d]+, in .+|\[Previous line repeated (\d+) more times\])"#,
        )
        .unwrap();
        Ok(stacktrace[first..first + last]
            .iter()
            .rev()
            .map(|s| s.trim().to_string())
            .filter(|s| re.is_match(s))
            .collect::<Vec<String>>())
    }

    /// Extract stack trace object from python traceback string
    ///
    /// # Arguments
    ///
    /// * `entries` - traceback as vector
    ///
    /// # Return value
    ///
    /// Traceback as a `Stacktrace` struct
    fn parse_stacktrace(entries: &[String], _: Option<&[String]>) -> Result<Stacktrace> {
        let mut stacktrace = Stacktrace::new();

        for entry in entries.iter() {
            let mut stentry = StacktraceEntry::default();

            if entry.starts_with('[') {
                let re = Regex::new(r#"\[Previous line repeated (\d+) more times\]"#).unwrap();
                if let Some(rep) = re.captures(entry) {
                    let Ok(rep) = rep.get(1).unwrap().as_str().parse::<u64>() else {
                        bail!("Couldn't parse num: {entry}");
                    };
                    let last = stacktrace.last().unwrap().clone();
                    for _ in 0..rep {
                        stentry = last.clone();
                        stacktrace.push(stentry);
                    }
                    continue;
                } else {
                    bail!("Couldn't parse stacktrace line: {entry}");
                }
            }

            let re = Regex::new(r#"File "(.+)", line (\d+), in (.+)"#).unwrap();

            if let Some(cap) = re.captures(entry) {
                stentry.debug.file = cap.get(1).unwrap().as_str().to_string();
                if let Ok(line) = cap.get(2).unwrap().as_str().parse::<u64>() {
                    stentry.debug.line = line;
                } else {
                    bail!("Couldn't parse stacktrace line num: {entry}");
                };
                stentry.function = cap.get(3).unwrap().as_str().to_string();
            } else {
                bail!("Couldn't parse stacktrace line: {entry}");
            }

            stacktrace.push(stentry);
        }
        Ok(stacktrace)
    }
}

impl Exception for PythonAnalysis {
    /// Get exception from python report.                                            
    ///                                                                              
    /// # Arguments                                                                  
    ///                                                                              
    /// * `exception_line` - python exception line                                   
    ///                                                                              
    /// # Return value                                                               
    ///                                                                              
    /// ExecutionClass with python exception info                                    
    fn parse_exception(stderr_list: &[String]) -> Option<ExecutionClass> {
        let re = Regex::new(r#"([\w]+): (.+)"#).unwrap();
        stderr_list
            .iter()
            .rev()
            .find_map(|x| re.captures(x))
            .map(|cap| {
                ExecutionClass::new((
                    "UNDEFINED",
                    cap.get(1).unwrap().as_str(),
                    cap.get(2).unwrap().as_str(),
                    "",
                ))
            })
    }
}
