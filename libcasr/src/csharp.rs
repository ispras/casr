//! C Sharp module implements `ParseStacktrace` and `Exception` traits for C Sharp reports.
use crate::exception::Exception;
use crate::stacktrace::ParseStacktrace;

use crate::error::*;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::StacktraceEntry;

use regex::Regex;

/// Structure provides an interface for processing the stack trace.
pub struct CSharpStacktrace;

impl ParseStacktrace for CSharpStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let re = Regex::new(r"(?m)^Unhandled Exception:(?:.|\n)+?((?:\n[^\S\n]*(?:at .+|--- End of inner exception stack trace ---))+)$").unwrap();

        let Some(cap) = re.captures(stream) else {
            return Err(Error::Casr("Couldn't find stacktrace".to_string()));
        };

        Ok(cap
            .get(1)
            .unwrap()
            .as_str()
            .split('\n')
            .scan(false, |skip, s| {
                let f = s.contains("--- End of inner exception stack trace ---");
                if *skip || f {
                    *skip = f;
                    return Some("");
                }
                Some(s)
            })
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let re = Regex::new(r"at (?:\(.+\) )?(.+?) ?\(.*\) <(\S+?).+> in (.+):(\d+)").unwrap();

        let Some(cap) = re.captures(entry) else {
            return Err(Error::Casr(format!("Couldn't parse stacktrace line: {entry}")));
        };

        let mut stentry = StacktraceEntry::default();

        let Ok(line) = cap.get(4).unwrap().as_str().parse::<u64>() else {
            return Err(Error::Casr(format!("Couldn't parse stacktrace line num: {entry}")));
        };

        stentry.debug.line = line;
        stentry.function = cap.get(1).unwrap().as_str().to_string();
        stentry.debug.file = cap.get(3).unwrap().as_str().to_string();

        Ok(stentry)
    }
}

/// Structure provides an interface for parsing c sharp exception message.
pub struct CSharpException;

impl Exception for CSharpException {
    fn parse_exception(stream: &str) -> Option<ExecutionClass> {
        let re = Regex::new(r"(?m)^Unhandled Exception:\n((?:.|\n)+?)\n[^\S\n]*at .+$").unwrap();

        let description = re.captures(stream)?
            .get(1)?
            .as_str();

        let v: Vec<&str> = description.rsplit_once("---> ")
            .map_or(description, |(_, s)| s)
            .splitn(2, ": ")
            .collect();

        Some(ExecutionClass { short_description: v[0].to_string(), description: v[1].to_string(), ..ExecutionClass::default()})
    }
}