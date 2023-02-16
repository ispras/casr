use anyhow::{bail, Result};
use gdb_command::stacktrace::*;
use regex::Regex;

use crate::error;
use crate::execution_class::ExecutionClass;
use crate::gdb::is_near_null;
use crate::gdb::CrashContext;
use crate::stacktrace::ProcessStacktrace;
use crate::util::Severity;

pub struct AsanAnalysis;

impl ProcessStacktrace for AsanAnalysis {
    /// Detect stack trace in sanitizer report
    ///
    /// # Arguments
    ///
    /// * `stream` - sanitizer report
    ///
    /// # Return value
    ///
    /// Stack trace as vector of strings
    fn detect_stacktrace(stream: &str) -> Result<Vec<String>> {
        let lines: Vec<String> = stream.split('\n').map(|l| l.trim().to_string()).collect();

        let frame = Regex::new(r"^#0 ").unwrap();
        let first = lines.iter().position(|x| frame.is_match(x));
        if first.is_none() {
            bail!("Couldn't find stack trace in sanitizer's report");
        }

        // Stack trace is splitted by empty line.
        let first = first.unwrap();
        let last = lines.iter().skip(first).position(|val| val.is_empty());
        if last.is_none() {
            bail!("Couldn't find stack trace end in sanitizer's report");
        }
        let last = last.unwrap();
        Ok(lines[first..first + last].to_vec())
    }

    /// Extract stack trace object from asan stack trace vector of string
    ///
    /// # Arguments
    ///
    /// * `entries` - stack trace as vector
    ///
    /// # Return value
    ///
    /// Stack trace as a `Stacktrace` struct
    fn parse_stacktrace(entries: &[String], _: Option<&[String]>) -> Result<Stacktrace> {
        let mut stacktrace = Stacktrace::new();
        for entry in entries.iter() {
            let mut stentry = StacktraceEntry::default();

            // #10 0xdeadbeef
            let re = Regex::new(r"^ *#[0-9]+ +0x([0-9a-f]+) *").unwrap();
            let caps = re.captures(entry.as_ref());
            if caps.is_none() {
                bail!("Couldn't parse frame and address in stack trace entry: {entry}");
            }
            let caps = caps.unwrap();

            // Get address.
            let num = caps.get(1).unwrap().as_str();
            let addr = u64::from_str_radix(num, 16);
            if addr.is_err() {
                bail!("Couldn't parse address: {num}");
            }
            stentry.address = addr.unwrap();

            // Cut frame and address from string.
            let mut location = entry[caps.get(0).unwrap().as_str().len()..].trim();

            // Determine whether entry has function name.
            // TODO: there may be no function and source path may start with in and space.
            let has_function = location.starts_with("in ");

            // (module+0xdeadbeef)
            // TODO: (module)
            // We have to distinguish from (anonymous namespace) and function arguments.
            // TODO: module path may contain (.
            // We forbid ( in module path to distinguish from function arguments.
            // However, we allow ( when there is no function.
            // Regex::captures returns leftmost-first match, so, it won't match (BuildId: ).
            let re = if has_function {
                Regex::new(r"\(([^(]+)\+0x([0-9a-f]+)\)").unwrap()
            } else {
                Regex::new(r"\((.+)\+0x([0-9a-f]+)\)").unwrap()
            };
            if let Some(caps) = re.captures(location.as_ref()) {
                // Get module name.
                stentry.module = caps.get(1).unwrap().as_str().trim().to_string();
                // Get offset in module.
                let num = caps.get(2).unwrap().as_str();
                let off = u64::from_str_radix(num, 16);
                if off.is_err() {
                    bail!("Couldn't parse module offset: {num}");
                }
                stentry.offset = off.unwrap();
                // Cut module from string.
                location = location[..caps.get(0).unwrap().start()].trim();
            }

            // in function[(args)] [const] path
            // TODO: source file path may contain )
            if has_function {
                location = location[3..].trim();
                if location.is_empty() {
                    bail!("Couldn't parse function name: {entry}");
                }
                let i = if let Some(p) = location.rfind(')') {
                    if location[p..].starts_with(") const ") {
                        p + 7
                    } else {
                        p
                    }
                } else {
                    location.find(' ').unwrap_or(0)
                };
                let space_after_paren = location[i..].find(' ');
                if space_after_paren.is_none() {
                    // Get function name.
                    stentry.function = location.to_string();
                    // No source path.
                    stacktrace.push(stentry);
                    continue;
                }
                let space_after_paren = space_after_paren.unwrap() + i;
                // Get function name.
                stentry.function = location[..space_after_paren].to_string();
                // Cut function name from string.
                location = location[space_after_paren..].trim();
            }

            // file[:line[:column]]
            // TODO: path may contain :
            if !location.is_empty() {
                let source: Vec<&str> = location.rsplitn(3, ':').collect();
                if source.iter().any(|x| x.is_empty()) {
                    bail!("Couldn't parse source file path, line, or column: {location}");
                }
                // Get source file.
                stentry.debug.file = source.last().unwrap().trim().to_string();
                // Get source line (optional).
                if source.len() > 1 {
                    let num = source[source.len() - 2];
                    let line = num.parse::<u64>();
                    if line.is_err() {
                        bail!("Couldn't parse source line: {num}");
                    }
                    stentry.debug.line = line.unwrap();
                }
                // Get source column (optional).
                if source.len() == 3 {
                    let num = source[0];
                    let column = num.parse::<u64>();
                    if column.is_err() {
                        bail!("Couldn't parse source column: {num}");
                    }
                    stentry.debug.column = column.unwrap();
                }
            }

            stacktrace.push(stentry);
        }
        Ok(stacktrace)
    }
}

impl Severity for AsanAnalysis {
    fn severity<'a>(
        _: &CrashContext,
        asan_report: &'a [String],
    ) -> error::Result<ExecutionClass<'a>> {
        if asan_report[0].contains("LeakSanitizer") {
            return Ok(ExecutionClass::find("memory-leaks").unwrap());
        } else {
            let summary = Regex::new(r"SUMMARY: *(AddressSanitizer|libFuzzer): (\S+)").unwrap();

            if let Some(caps) = asan_report.iter().find_map(|s| summary.captures(s)) {
                // Match Sanitizer.
                match caps.get(1).unwrap().as_str() {
                    "libFuzzer" => {
                        if let Ok(class) =
                            ExecutionClass::san_find(caps.get(2).unwrap().as_str(), None, false)
                        {
                            return Ok(class);
                        }
                    }
                    _ => {
                        // AddressSanitizer
                        let san_type = caps.get(2).unwrap().as_str();
                        let mem_access = if let Some(second_line) = asan_report.get(1) {
                            let raccess = Regex::new(r"(READ|WRITE|ACCESS)").unwrap();
                            if let Some(access_type) = raccess.captures(second_line) {
                                Some(access_type.get(1).unwrap().as_str())
                            } else if let Some(third_line) = asan_report.get(2) {
                                raccess
                                    .captures(third_line)
                                    .map(|access_type| access_type.get(1).unwrap().as_str())
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        let rcrash_address = Regex::new("on.*address 0x([0-9a-f]+)").unwrap();
                        let near_null =
                            if let Some(crash_address) = rcrash_address.captures(&asan_report[0]) {
                                is_near_null(u64::from_str_radix(
                                    crash_address.get(1).unwrap().as_str(),
                                    16,
                                )?)
                            } else {
                                false
                            };
                        if let Ok(class) = ExecutionClass::san_find(san_type, mem_access, near_null)
                        {
                            return Ok(class);
                        }
                    }
                }
            }
        }
        Ok(Default::default())
    }
}
