//! Python module implements `ParseStacktrace` and `Exception` traits for Python reports.
use crate::exception::Exception;
use crate::stacktrace::ParseStacktrace;

use crate::error::*;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::*;
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
            .position(|line| line.starts_with("Traceback "))
        else {
            return Err(Error::Casr(
                "Couldn't find traceback in python report".to_string(),
            ));
        };

        // Stack trace is split by empty line.
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

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let mut stentry = StacktraceEntry::default();
        let re = Regex::new(r#"File "(.+)", line (\d+), in (.+)"#).unwrap();

        let Some(cap) = re.captures(entry) else {
            return Err(Error::Casr(format!(
                "Couldn't parse stacktrace line: {entry}"
            )));
        };
        stentry.debug.file = cap.get(1).unwrap().as_str().to_string();
        if let Ok(line) = cap.get(2).unwrap().as_str().parse::<u64>() {
            stentry.debug.line = line;
        } else {
            return Err(Error::Casr(format!(
                "Couldn't parse stacktrace line number: {entry}"
            )));
        };
        stentry.function = cap.get(3).unwrap().as_str().to_string();

        Ok(stentry)
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        let mut stacktrace = Stacktrace::new();

        let re = Regex::new(r"\[Previous line repeated (\d+) more times\]").unwrap();
        for entry in entries.iter() {
            if entry.starts_with('[') {
                let Some(rep) = re.captures(entry) else {
                    return Err(Error::Casr(format!(
                        "Couldn't parse stacktrace line: {entry}"
                    )));
                };
                let Ok(rep) = rep.get(1).unwrap().as_str().parse::<u64>() else {
                    return Err(Error::Casr(format!("Couldn't parse num: {entry}")));
                };
                let last = stacktrace.last().unwrap().clone();
                for _ in 0..rep {
                    stacktrace.push(last.clone());
                }
                continue;
            }

            stacktrace.push(Self::parse_stacktrace_entry(entry)?);
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
        let re = Regex::new(r"([\w]+): (.+)").unwrap();
        stderr_list
            .iter()
            .rev()
            .find_map(|x| re.captures(x))
            .map(|cap| {
                ExecutionClass::new((
                    "NOT_EXPLOITABLE",
                    cap.get(1).unwrap().as_str(),
                    cap.get(2).unwrap().as_str(),
                    "",
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_stacktrace() {
        let raw_stacktrace = &[
            "File \"<stdin>\", line 1, in <module>",
            "File \"/usr/lib/python3.10/site-packages/PIL/Image.py\", line 2259, in show",
            "File \"/usr/lib/python3.10/site-packages/PIL/Image.py\", line 3233, in _show",
            "File \"/usr/lib/python3.10/site-packages/PIL/ImageShow.py\", line 55, in show",
            "File \"/usr/lib/python3.10/site-packages/PIL/ImageShow.py\", line 79, in show",
            "File \"/usr/lib/python3.10/site-packages/PIL/ImageShow.py\", line 105, in show_image",
            "File \"/usr/lib/python3.10/site-packages/PIL/ImageShow.py\", line 212, in show_file",
            "File \"/usr/lib/python3.10/subprocess.py\", line 966, in __init__",
            "[Previous line repeated 3 more times]",
            "File \"/usr/lib/python3.10/subprocess.py\", line 1775, in _execute_child",
        ];
        let trace = raw_stacktrace
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();
        let sttr = PythonStacktrace::parse_stacktrace(&trace);
        if sttr.is_err() {
            panic!("{}", sttr.err().unwrap());
        }

        let stacktrace = sttr.unwrap();
        assert_eq!(stacktrace[0].debug.file, "<stdin>".to_string());
        assert_eq!(stacktrace[0].debug.line, 1);
        assert_eq!(stacktrace[0].function, "<module>".to_string());
        assert_eq!(
            stacktrace[1].debug.file,
            "/usr/lib/python3.10/site-packages/PIL/Image.py".to_string()
        );
        assert_eq!(stacktrace[1].debug.line, 2259);
        assert_eq!(stacktrace[1].function, "show".to_string());
        assert_eq!(
            stacktrace[2].debug.file,
            "/usr/lib/python3.10/site-packages/PIL/Image.py".to_string()
        );
        assert_eq!(stacktrace[2].debug.line, 3233);
        assert_eq!(stacktrace[2].function, "_show".to_string());
        assert_eq!(
            stacktrace[3].debug.file,
            "/usr/lib/python3.10/site-packages/PIL/ImageShow.py".to_string()
        );
        assert_eq!(stacktrace[3].debug.line, 55);
        assert_eq!(stacktrace[3].function, "show".to_string());
        assert_eq!(
            stacktrace[4].debug.file,
            "/usr/lib/python3.10/site-packages/PIL/ImageShow.py".to_string()
        );
        assert_eq!(stacktrace[4].debug.line, 79);
        assert_eq!(stacktrace[4].function, "show".to_string());
        assert_eq!(
            stacktrace[5].debug.file,
            "/usr/lib/python3.10/site-packages/PIL/ImageShow.py".to_string()
        );
        assert_eq!(stacktrace[5].debug.line, 105);
        assert_eq!(stacktrace[5].function, "show_image".to_string());
        assert_eq!(
            stacktrace[6].debug.file,
            "/usr/lib/python3.10/site-packages/PIL/ImageShow.py".to_string()
        );
        assert_eq!(stacktrace[6].debug.line, 212);
        assert_eq!(stacktrace[6].function, "show_file".to_string());
        assert_eq!(
            stacktrace[7].debug.file,
            "/usr/lib/python3.10/subprocess.py".to_string()
        );
        assert_eq!(stacktrace[7].debug.line, 966);
        assert_eq!(stacktrace[7].function, "__init__".to_string());
        assert_eq!(
            stacktrace[8].debug.file,
            "/usr/lib/python3.10/subprocess.py".to_string()
        );
        assert_eq!(stacktrace[8].debug.line, 966);
        assert_eq!(stacktrace[8].function, "__init__".to_string());
        assert_eq!(
            stacktrace[9].debug.file,
            "/usr/lib/python3.10/subprocess.py".to_string()
        );
        assert_eq!(stacktrace[9].debug.line, 966);
        assert_eq!(stacktrace[9].function, "__init__".to_string());
        assert_eq!(
            stacktrace[10].debug.file,
            "/usr/lib/python3.10/subprocess.py".to_string()
        );
        assert_eq!(stacktrace[10].debug.line, 966);
        assert_eq!(stacktrace[10].function, "__init__".to_string());
        assert_eq!(
            stacktrace[11].debug.file,
            "/usr/lib/python3.10/subprocess.py".to_string()
        );
        assert_eq!(stacktrace[11].debug.line, 1775);
        assert_eq!(stacktrace[11].function, "_execute_child".to_string());
    }
}
