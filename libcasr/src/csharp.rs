//! C Sharp module implements `ParseStacktrace` and `Exception` traits for C Sharp reports.
use crate::exception::Exception;
use crate::stacktrace::{ParseStacktrace, Stacktrace};

use crate::error::*;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::StacktraceEntry;

use regex::Regex;

#[derive(Copy, Clone)]
enum StacktraceFormat {
    Mono,
    dotNET
}

impl StacktraceFormat {
    fn get_regex_for_stacktrace_entry(&self) -> Regex {
        match self {
            StacktraceFormat::Mono => Regex::new(r"^at (?:\(.+?\) )?(?P<function>\S+)(?P<params> ?\(.*?\))? (?:<(?P<base>\w+) \+ (?P<offset>\w+)>|\[0x[\da-fA-F]+\]) in (?:<[\da-fA-F]+>|(?P<file>.+)):(?P<line>\w+)$"),
            StacktraceFormat::dotNET => Regex::new(r"^at (?:\(.+?\) )?(?P<function>\S+)(?P<params>\(.*?\))?(?: in (?P<file>.+):line (?P<line>\w+))?$")
        }.unwrap()
    }

    fn get_format_by_stacktrace_entry(entry: &str) -> Result<StacktraceFormat> {
        for format in [StacktraceFormat::Mono, StacktraceFormat::dotNET] {
            if format.get_regex_for_stacktrace_entry().is_match(entry) {
                return Ok(format);
            }
        }

        return Err(Error::Casr(format!("Couldn't parse stacktrace line: {entry}")));
    }
}
/// Structure provides an interface for processing the stack trace.
pub struct CSharpStacktrace;

impl CSharpStacktrace {
    fn parse_stacktrace_entry(entry: &str, format: StacktraceFormat) -> Result<StacktraceEntry> {
        let re = format.get_regex_for_stacktrace_entry();

        let Some(cap) = re.captures(entry) else {
            return Err(Error::Casr(format!("Couldn't parse stacktrace line: {entry}")));
        };

        let get_group_by_name_as_str = |name| cap.name(name).map(|m| m.as_str());

        let mut stentry = StacktraceEntry::default();

        if let Some(file) = get_group_by_name_as_str("file") {
            stentry.debug.file = file.to_string();
        }

        if let Some(line) = get_group_by_name_as_str("line") {
            match line.parse::<u64>() {
                Ok(parsed_line) if Regex::new(r"^\d+$").unwrap().is_match(line) => stentry.debug.line = parsed_line,
                _ => return Err(Error::Casr(format!("Couldn't parse stacktrace line num: {entry}")))
            }
        }

        if let (Some(base), Some(offset)) = (get_group_by_name_as_str("base"), get_group_by_name_as_str("offset")) {
            let parse_hex = |s| Regex::new(r"^0x([\da-fA-F]+)$")
                .unwrap()
                .captures(s)
                .and_then(|c| c.get(1))
                .and_then(|m| u64::from_str_radix(m.as_str(), 16).ok());

            stentry.address = (|| {
                if let (Some(base), Some(offset)) = (parse_hex(base), parse_hex(offset)) {
                    if let Some(address) = base.checked_add(offset) {
                        return Ok(address)
                    }
                }

                return Err(Error::Casr(format!("Couldn't parse address: {base} + {offset}")));
            })()?;
        }


        if let Some(function) = get_group_by_name_as_str("function") {
            let mut function = function.to_string();
            if let Some(params) = get_group_by_name_as_str("params") {
                function.push_str(params)
            }

            stentry.function = function;
        }

        Ok(stentry)
    }
}

impl ParseStacktrace for CSharpStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let re = Regex::new(r"(?m)^Unhandled ([Ee])xception(:\n|\. )(?:.|\n)+?((?:\n\s*(?:at [\S ]+|--- End of inner exception stack trace ---))+)$").unwrap();

        let Some(cap) = re.captures(stream).and_then(|cap|
            ((cap.get(1).unwrap().as_str() == "E") == (cap.get(2).unwrap().as_str() == ":\n")).then_some(cap)
        ) else {
            return Err(Error::Casr("The stacktrace format is not recognized".to_string()));
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
        Self::parse_stacktrace_entry(entry, StacktraceFormat::get_format_by_stacktrace_entry(entry)?)
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        let mut iter = entries
            .iter()
            .scan((true, false), |(first_block, skip), s| {
                // Skipping all blocks consisting of "--- End of inner exception stack trace ---"
                // and one stack frame after each such block, except for the first block if entries start with it.
                let not_stack_trace_entry = s == "--- End of inner exception stack trace ---";

                if not_stack_trace_entry || *skip {
                    *skip = not_stack_trace_entry;

                    if !*first_block || not_stack_trace_entry {
                        return Some("");
                    }
                }

                *first_block = false;

                Some(s)
            })
            .filter(|&s| !s.is_empty()).peekable();

        if let Some(s) = iter.peek() {
            let f = StacktraceFormat::get_format_by_stacktrace_entry(s)?;

            return iter.map(|s| Self::parse_stacktrace_entry(s, f)).collect()
        }

        return std::iter::empty::<Result<StacktraceEntry>>().collect();
    }
}

/// Structure provides an interface for parsing c sharp exception message.
pub struct CSharpException;

impl Exception for CSharpException {
    fn parse_exception(stream: &str) -> Option<ExecutionClass> {
        let re_mono = Regex::new(r"(?m)^Unhandled Exception:\n((?:.|\n)+?(?: ---> (?:.|\n)+?)*?)\n\s*(?:at .+|--- End of inner exception stack trace ---)$").unwrap();
        let re_dotnet = Regex::new(r"(?m)^Unhandled exception\. ((?:.|\n)+?(?:\n ---> (?:.|\n)+?)*?)\n\s*(?:at .+|--- End of inner exception stack trace ---)$").unwrap();

        let description = re_mono.captures(stream)
            .or(re_dotnet.captures(stream))?
            .get(1)?
            .as_str();

        let (exception, message) = description
            .trim_start()
            .rsplit_once(" ---> ")
            .map_or(description, |(_, s)| s)
            .split_once(": ")
            .unwrap();

        Some(ExecutionClass { short_description: exception.to_string(), description: message.to_string(), ..ExecutionClass::default()})
    }
}
