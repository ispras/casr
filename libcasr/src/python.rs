//! Python module implements `ParseStacktrace` and `Exception` traits for Python reports.
use regex::Regex;

use crate::{
    error::{Error, Result},
    exception::Exception,
    execution_class::ExecutionClass,
    report::ReportExtractor,
    stacktrace::{CrashLine, ParseStacktrace, Stacktrace, StacktraceContext, StacktraceEntry},
};

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
pub struct PythonException {
    context: StacktraceContext,
    exception: String,
}

impl PythonException {
    /// Create new `PythonException` instance from Python output
    fn new_from_python(stream: &str) -> Result<Option<Self>> {
        let stream: Vec<String> = stream.split('\n').map(|l| l.trim().to_string()).collect();
        let Some(start) = stream.iter().position(|l| l.contains("Traceback ")) else {
            return Ok(None::<Self>);
        };
        let Some(end) = stream.iter().rposition(|s| !s.is_empty()) else {
            return Err(Error::Casr(
                "Corrupted output: can't find stderr end".to_string(),
            ));
        };
        let end = end + 1;
        let report = &stream[start..end];
        Ok(Some(Self {
            context: StacktraceContext::new(report.join("\n"), None),
            exception: report.last().unwrap().to_string(),
        }))
    }
    /// Create new `PythonException` instance from Atheris output
    fn new_from_atheris(stream: &str) -> Result<Option<Self>> {
        let stream: Vec<String> = stream.split('\n').map(|l| l.trim().to_string()).collect();
        let Some(start) = stream
            .iter()
            .position(|line| line.contains("Uncaught Python exception: "))
        else {
            return Ok(None::<Self>);
        };
        let Some(end) = stream.iter().rposition(|s| !s.is_empty()) else {
            return Err(Error::Casr(
                "Corrupted output: can't find stderr end".to_string(),
            ));
        };
        let end = end + 1;
        let report = &stream[start..end];
        if report.len() <= 1 {
            return Ok(None::<Self>);
        }
        Ok(Some(Self {
            context: StacktraceContext::new(report.join("\n"), None),
            exception: report[1].clone(),
        }))
    }
    /// Create new `PythonException` instance from stream
    pub fn new(stdout: &str, stderr: &str) -> Result<Option<Self>> {
        if stderr.contains("== ERROR: libFuzzer: ") {
            Self::new_from_atheris(stdout)
        } else {
            Self::new_from_python(stderr)
        }
    }
}

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

impl ReportExtractor for PythonException {
    fn extract_stacktrace(&mut self) -> Result<Vec<String>> {
        self.context.extract_stacktrace::<PythonStacktrace>()
    }
    fn parse_stacktrace(&mut self) -> Result<Stacktrace> {
        self.context.parse_stacktrace::<PythonStacktrace>()
    }
    fn crash_line(&mut self) -> Result<CrashLine> {
        self.context.crash_line::<PythonStacktrace>()
    }
    fn stream(&self) -> &str {
        self.context.stream()
    }
    fn report(&self) -> Vec<String> {
        self.context.report()
    }
    fn execution_class(&self) -> Result<ExecutionClass> {
        let Some(class) = PythonException::parse_exception(&self.exception) else {
            return Err(Error::Casr("Python exception is not found!".to_string()));
        };
        Ok(class)
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

    #[test]
    fn test_python_extractor() {
        let stdout = "
             === Uncaught Python exception: ===
            ZeroDivisionError: division by zero
            Traceback (most recent call last):
              File \"/casr/tests/casr_tests/python/./test_casr_python_atheris.py\", line 14, in TestOneInput
                crash_found(data)
              File \"/casr/tests/casr_tests/python/./test_casr_python_atheris.py\", line 10, in crash_found
                return 1/0
            ZeroDivisionError: division by zero";
        let stderr = "
            INFO: Using built-in libfuzzer
            WARNING: Failed to find function \"__sanitizer_acquire_crash_state\".
            WARNING: Failed to find function \"__sanitizer_print_stack_trace\".
            WARNING: Failed to find function \"__sanitizer_set_death_callback\".
            INFO: Running with entropic power schedule (0xFF, 100).
            INFO: Seed: 1814056484
            ./test_casr_python_atheris.py: Running 1 inputs 1 time(s) each.
            Running: crash
            ==12147== ERROR: libFuzzer: fuzz target exited
            SUMMARY: libFuzzer: fuzz target exited";

        let Ok(Some(mut exception)) = PythonException::new(stdout, stderr) else {
            panic!("Can't extract Python exception");
        };

        let lines = exception.report();
        assert_eq!(lines.len(), 8);

        let sttr = exception.extract_stacktrace();
        let Ok(sttr) = sttr else {
            panic!("{}", sttr.err().unwrap());
        };
        assert_eq!(sttr.len(), 2);

        let sttr = ReportExtractor::parse_stacktrace(&mut exception);
        let Ok(sttr) = sttr else {
            panic!("{}", sttr.err().unwrap());
        };
        assert_eq!(sttr.len(), 2);
        assert_eq!(
            sttr[0].debug.file,
            "/casr/tests/casr_tests/python/./test_casr_python_atheris.py".to_string()
        );
        assert_eq!(sttr[0].debug.line, 10);
        assert_eq!(sttr[0].function, "crash_found".to_string());
        assert_eq!(
            sttr[1].debug.file,
            "/casr/tests/casr_tests/python/./test_casr_python_atheris.py".to_string()
        );
        assert_eq!(sttr[1].debug.line, 14);
        assert_eq!(sttr[1].function, "TestOneInput".to_string());

        let crashline = exception.crash_line();
        let Ok(crashline) = crashline else {
            panic!("{}", crashline.err().unwrap());
        };
        assert_eq!(
            crashline.to_string(),
            "/casr/tests/casr_tests/python/./test_casr_python_atheris.py:10"
        );

        let execution_class = exception.execution_class();
        let Ok(execution_class) = execution_class else {
            panic!(
                "Execution class is corrupted: {}",
                execution_class.err().unwrap()
            );
        };
        assert_eq!(execution_class.severity, "NOT_EXPLOITABLE");
        assert_eq!(execution_class.short_description, "ZeroDivisionError");
        assert_eq!(execution_class.description, "division by zero");
        assert_eq!(execution_class.explanation, "");
    }
}
