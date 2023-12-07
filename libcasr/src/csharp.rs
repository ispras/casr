//! C Sharp module implements `ParseStacktrace` and `Exception` traits for C Sharp reports.
use crate::exception::Exception;
use crate::stacktrace::{ParseStacktrace, Stacktrace};

use crate::error::*;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::StacktraceEntry;

use regex::Regex;

/// Structure provides an interface for processing the stack trace.
pub struct CSharpStacktrace;

impl CSharpStacktrace {
    fn parse_stacktrace_entry_with_format(entry: &str, use_mono_format: bool) -> Result<StacktraceEntry> {
        let re =
            if use_mono_format { Regex::new(r"at (?:\(.+\) )?(.+?) ?\(.*\) (?:<0x(?<address>\w+).+>|\[\w+]) in (?<file>.+):(?<line>\d+)") }
            else { Regex::new(r"at (?:\(.+\) )?(.+?)\(.*\) in (?<file>.+):line (?<line>\d+)") }.unwrap();

        let Some(cap) = re.captures(entry) else {
            return Err(Error::Casr(format!("Couldn't parse stacktrace line: {entry}")));
        };

        let mut stentry = StacktraceEntry::default();

        if let Some(num) = cap.name("address").map(|m| m.as_str()) {
            if let Ok(address) = u64::from_str_radix(num, 16) {
                stentry.address = address;
            } else {
                return Err(Error::Casr(format!("Couldn't parse address: {num}")));
            }
        }

        let Ok(line) = cap.name("line").unwrap().as_str().parse::<u64>() else {
            return Err(Error::Casr(format!("Couldn't parse stacktrace line num: {entry}")));
        };

        stentry.function = cap.get(1).unwrap().as_str().to_string();
        stentry.debug.file = cap.name("file").unwrap().as_str().to_string();
        stentry.debug.line = line;
        Ok(stentry)
    }
}

impl ParseStacktrace for CSharpStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let re = Regex::new(r"(?m)^Unhandled ([Ee])xception(:\n|\. )(?:.|\n)+?((?:\n[^\S\n]*(?:at.+|--- End of inner exception stack trace ---))+)$").unwrap();

        let Some(cap) = re.captures(stream).and_then(|cap|
            ((cap.get(1).unwrap().as_str() == "E") == (cap.get(2).unwrap().as_str() == ":\n")).then_some(cap)
        ) else {
            return Err(Error::Casr("Couldn't find stacktrace".to_string()));
        };

        Ok(cap
            .get(3)
            .unwrap()
            .as_str()
            .split('\n')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        Self::parse_stacktrace_entry_with_format(entry, true)
            .or(Self::parse_stacktrace_entry_with_format(entry, false))
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        let mut iter = entries
            .iter()
            .scan((true, false), |(cancel_skip, skip), s| {
                // Skipping all blocks consisting of "--- End of inner exception stack trace ---"
                // and one stack frame after each such block, except for the first block if entries start with it.
                let not_stack_frame = s == "--- End of inner exception stack trace ---";

                if not_stack_frame || *skip {
                    *skip = not_stack_frame;

                    if !*cancel_skip || not_stack_frame {
                        return Some("");
                    }
                }

                *cancel_skip = false;

                Some(s)
            })
            .filter(|s| !s.is_empty()).peekable();

        let use_mono_format = iter.peek().and_then(|&s| {
            match Self::parse_stacktrace_entry_with_format(s, true) {
                Err(Error::Casr(ref s)) if s.starts_with("Couldn't parse stacktrace line:") => None,
                _ => Some(""),
            }
        }).is_some();

        iter
            .map(|s| Self::parse_stacktrace_entry_with_format(s, use_mono_format))
            .collect()
    }
}

/// Structure provides an interface for parsing c sharp exception message.
pub struct CSharpException;

impl Exception for CSharpException {
    fn parse_exception(stream: &str) -> Option<ExecutionClass> {
        let re = Regex::new(r"(?m)^Unhandled ([Ee])xception(:\n|\. )((?:.|\n)+?)\n[^\S\n]*(at.+|--- End of inner exception stack trace ---)$").unwrap();
        
        let description = re.captures(stream).and_then(|cap|
            ((cap.get(1).unwrap().as_str() == "E") == (cap.get(2).unwrap().as_str() == ":\n")).then_some(cap)
        )?.get(3)?
            .as_str();

        let v: Vec<&str> = description.trim_start().rsplit_once(" ---> ")
            .map_or(description, |(_, s)| s)
            .splitn(2, ": ")
            .collect();

        Some(ExecutionClass { short_description: v[0].to_string(), description: v.get(1)?.to_string(), ..ExecutionClass::default()})
    }
}