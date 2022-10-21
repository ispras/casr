use crate::error;
use gdb_command::stacktrace::*;
use regex::Regex;

/// Extract stack trace object from python traceback string
///
/// # Arguments
///
/// * `entries` - traceback as vector
///
/// # Return value
///
/// Traceback as a `Stacktrace` struct
pub fn stacktrace_from_python(entries: &[String]) -> error::Result<Stacktrace> {
    let mut stacktrace = Stacktrace::new();

    for entry in entries.iter() {
        let mut stentry = StacktraceEntry::default();

        if entry.starts_with('[') {
            let re = Regex::new(r#"\[Previous line repeated (\d+) more times\]"#).unwrap();
            if let Some(rep) = re.captures(entry) {
                let rep = rep.get(1).unwrap().as_str().parse::<u64>();
                if rep.is_err() {
                    return Err(error::Error::Casr(format!("Couldn't parse num: {}", entry)));
                }
                let rep = rep.unwrap();
                let last = stacktrace.last().unwrap().clone();
                for _ in 0..rep {
                    stentry = last.clone();
                    stacktrace.push(stentry);
                }
                continue;
            } else {
                return Err(error::Error::Casr(format!(
                    "Couldn't parse stacktrace line: {}",
                    entry
                )));
            }
        }

        let re = Regex::new(r#"File "(.+)", line (\d+), in (.+)"#).unwrap();

        if let Some(cap) = re.captures(entry) {
            stentry.debug.file = cap.get(1).unwrap().as_str().to_string();
            let line = cap.get(2).unwrap().as_str().parse::<u64>();
            if line.is_err() {
                return Err(error::Error::Casr(format!(
                    "Couldn't parse stacktrace line num: {}",
                    entry
                )));
            }
            stentry.debug.line = line.unwrap();
            stentry.function = cap.get(3).unwrap().as_str().to_string();
        } else {
            return Err(error::Error::Casr(format!(
                "Couldn't parse stacktrace line: {}",
                entry
            )));
        }

        stacktrace.push(stentry);
    }
    Ok(stacktrace)
}
