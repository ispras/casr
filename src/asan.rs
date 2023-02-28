use gdb_command::stacktrace::*;
use regex::Regex;

use crate::error::*;
use crate::execution_class::ExecutionClass;
use crate::gdb::is_near_null;
use crate::severity::Severity;
use crate::stacktrace::ParseStacktrace;

/// Structure provides an interface for processing the stack trace.
pub struct AsanStacktrace;

impl ParseStacktrace for AsanStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let lines: Vec<String> = stream.split('\n').map(|l| l.trim().to_string()).collect();

        let frame = Regex::new(r"^#0 ").unwrap();
        let first = lines.iter().position(|x| frame.is_match(x));
        if first.is_none() {
            return Err(Error::Casr(
                "Couldn't find stack trace in sanitizer's report".to_string(),
            ));
        }

        // Stack trace is splitted by empty line.
        let first = first.unwrap();
        let last = lines.iter().skip(first).position(|val| val.is_empty());
        if last.is_none() {
            return Err(Error::Casr(
                "Couldn't find stack trace end in sanitizer's report".to_string(),
            ));
        }
        let last = last.unwrap();
        Ok(lines[first..first + last].to_vec())
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        let mut stacktrace = Stacktrace::new();
        for entry in entries.iter() {
            let mut stentry = StacktraceEntry::default();

            // #10 0xdeadbeef
            let re = Regex::new(r"^ *#[0-9]+ +0x([0-9a-f]+) *").unwrap();
            let caps = re.captures(entry.as_ref());
            if caps.is_none() {
                return Err(Error::Casr(
                    "Couldn't parse frame and address in stack trace entry: {entry}".to_string(),
                ));
            }
            let caps = caps.unwrap();

            // Get address.
            let num = caps.get(1).unwrap().as_str();
            let addr = u64::from_str_radix(num, 16);
            if addr.is_err() {
                return Err(Error::Casr("Couldn't parse address: {num}".to_string()));
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
                    return Err(Error::Casr(
                        "Couldn't parse module offset: {num}".to_string(),
                    ));
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
                    return Err(Error::Casr(
                        "Couldn't parse function name: {entry}".to_string(),
                    ));
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
                    return Err(Error::Casr(
                        "Couldn't parse source file path, line, or column: {location}".to_string(),
                    ));
                }
                // Get source file.
                stentry.debug.file = source.last().unwrap().trim().to_string();
                // Get source line (optional).
                if source.len() > 1 {
                    let num = source[source.len() - 2];
                    let line = num.parse::<u64>();
                    if line.is_err() {
                        return Err(Error::Casr("Couldn't parse source line: {num}".to_string()));
                    }
                    stentry.debug.line = line.unwrap();
                }
                // Get source column (optional).
                if source.len() == 3 {
                    let num = source[0];
                    let column = num.parse::<u64>();
                    if column.is_err() {
                        return Err(Error::Casr(
                            "Couldn't parse source column: {num}".to_string(),
                        ));
                    }
                    stentry.debug.column = column.unwrap();
                }
            }

            stacktrace.push(stentry);
        }
        Ok(stacktrace)
    }
}

/// Information about sanitizer crash state.
pub struct AsanContext(pub Vec<String>);

impl Severity for AsanContext {
    fn severity(&self) -> Result<ExecutionClass> {
        let asan_report = &self.0;
        if asan_report[0].contains("LeakSanitizer") {
            ExecutionClass::find("memory-leaks")
        } else {
            let summary = Regex::new(r"SUMMARY: *(AddressSanitizer|libFuzzer): (\S+)").unwrap();

            let Some(caps) = asan_report.iter().find_map(|s| summary.captures(s)) else {
                return Err(Error::Casr("Cannot find SUMMARY in Sanitizer report".to_string()));
            };
            // Match Sanitizer.
            match caps.get(1).unwrap().as_str() {
                "libFuzzer" => ExecutionClass::san_find(caps.get(2).unwrap().as_str(), None, false),
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
                    let near_null = if let Some(crash_address) =
                        rcrash_address.captures(&asan_report[0])
                    {
                        let Ok(addr) = u64::from_str_radix(
                                crash_address.get(1).unwrap().as_str(),
                                16,
                            ) else {
                                return Err(Error::Casr(format!("Cannot parse address: {}", crash_address.get(1).unwrap().as_str())));
                            };
                        is_near_null(addr)
                    } else {
                        false
                    };
                    ExecutionClass::san_find(san_type, mem_access, near_null)
                }
            }
        }
    }
}
