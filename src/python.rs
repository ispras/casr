use crate::exception::Exception;
use crate::stacktrace::ParseStacktrace;

use crate::error::*;
use crate::execution_class::ExecutionClass;
use gdb_command::stacktrace::*;
use regex::Regex;

/// Structure provides an interface for processing the stack trace.
pub struct PythonStacktrace;

impl ParseStacktrace for PythonStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        // Get stack trace from python report.
        let stacktrace = stream
            .split('\n')
            .map(|l| l.to_string())
            .collect::<Vec<String>>();
        let Some(first) = stacktrace
            .iter()
            .position(|line| line.starts_with("Traceback ")) else {
            return Err(Error::Casr(
                "Couldn't find traceback in python report".to_string(),
            ));
        };

        // Stack trace is splitted by empty line.
        let Some(last) = stacktrace.iter().skip(first).rposition(|s| !s.is_empty()) else {
            return Err(Error::Casr(
                "Couldn't find traceback end in python report".to_string(),
            ));
        };

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

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        let mut stacktrace = Stacktrace::new();

        for entry in entries.iter() {
            let mut stentry = StacktraceEntry::default();

            if entry.starts_with('[') {
                let re = Regex::new(r#"\[Previous line repeated (\d+) more times\]"#).unwrap();
                let Some(rep) = re.captures(entry) else {
                    return Err(Error::Casr(
                        "Couldn't parse stacktrace line: {entry}".to_string(),
                    ));
                };
                let Ok(rep) = rep.get(1).unwrap().as_str().parse::<u64>() else {
                    return Err(Error::Casr("Couldn't parse num: {entry}".to_string()));
                };
                let last = stacktrace.last().unwrap().clone();
                for _ in 0..rep {
                    stentry = last.clone();
                    stacktrace.push(stentry);
                }
                continue;
            }

            let re = Regex::new(r#"File "(.+)", line (\d+), in (.+)"#).unwrap();

            let Some(cap) = re.captures(entry) else {
                return Err(Error::Casr(
                    "Couldn't parse stacktrace line: {entry}".to_string(),
                ));
            };
            stentry.debug.file = cap.get(1).unwrap().as_str().to_string();
            if let Ok(line) = cap.get(2).unwrap().as_str().parse::<u64>() {
                stentry.debug.line = line;
            } else {
                return Err(Error::Casr(
                    "Couldn't parse stacktrace line num: {entry}".to_string(),
                ));
            };
            stentry.function = cap.get(3).unwrap().as_str().to_string();

            stacktrace.push(stentry);
        }
        Ok(stacktrace)
    }
}

/// Structure provides an interface for parsing python exception message.
pub struct PythonException;

impl Exception for PythonException {
    fn parse_exception(stderr: &str) -> Option<ExecutionClass> {
        let stderr_list: Vec<String> = stderr
            .split('\n')
            .map(|l| l.trim_end().to_string())
            .collect();
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
