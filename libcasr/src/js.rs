//! JS module implements `ParseStacktrace` and `Exception` traits for JS reports.
use crate::error::{Error, Result};
use crate::exception::Exception;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::{DebugInfo, ParseStacktrace, Stacktrace, StacktraceEntry};

use regex::Regex;

/// Structure provides an interface for parsing JS exception message.
pub struct JsException;

impl Exception for JsException {
    fn parse_exception(stderr: &str) -> Option<ExecutionClass> {
        let rexception = Regex::new(r"(?m)^.*?(\S*Error):(?:\s+(.*))?$").unwrap();
        let captures = rexception.captures(stderr)?;
        let error_type = captures.get(1).unwrap().as_str();
        let message = if let Some(message) = captures.get(2) {
            message.as_str()
        } else {
            ""
        };
        Some(ExecutionClass::new((
            "NOT_EXPLOITABLE",
            error_type,
            message,
            "",
        )))
    }
}

/// Structure provides an interface for processing the stack trace.
pub struct JsStacktrace;

impl ParseStacktrace for JsStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        // Get stack trace from JS report.
        let re = Regex::new(r"(?m)^(?:(?:.*Error:)(?:.|\n)*?|Thrown at:\n*?)((?:\n\s*at \S+.*)+)")
            .unwrap();
        let Some(cap) = re.captures(stream) else {
            return Err(Error::Casr(
                "Couldn't find traceback in JS report".to_string(),
            ));
        };
        // Filter out empty lines, leading and trailind spaces, multiple spaces
        let re = Regex::new(r" +").unwrap();
        let stacktrace = cap
            .get(1)
            .unwrap()
            .as_str()
            .split('\n')
            .filter(|l| !l.is_empty())
            .map(|l| l.trim().to_string())
            .map(|e| re.replace_all(&e, " ").to_string())
            .collect::<Vec<String>>();

        Ok(stacktrace)
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let mut stentry = StacktraceEntry::default();
        let re_full = Regex::new(r"^\s*at\s+(.+?)(?:\s+(\[as.*?\])?\s*)\((.*)\)$").unwrap();
        let re_without_pars = Regex::new(r"^\s*at\s+(.+?)(?:(?:\s+(\[as.*?\]))?\s*)$").unwrap();

        /// Parse substring of `entry` related to location in some file
        ///
        /// # Arguments
        ///
        /// * `loc` - substring to extract location information from
        ///
        /// # Return value
        ///
        /// Location information (if present): filename, line number, column number
        fn parse_location(loc: &str) -> Result<DebugInfo> {
            // filename[:line[:column]]
            let mut debug_info = DebugInfo::default();
            if loc.is_empty() {
                return Err(Error::Casr(format!("Couldn't parse location: {loc}")));
            }

            let mut debug: Vec<String> = loc.split(':').map(|s| s.to_string()).collect();
            if debug.len() > 3 {
                // Filename contains ':' so all the elements except
                // the last 2 belong to filename
                debug = loc.rsplitn(3, ':').map(|s| s.to_string()).collect();
                debug.reverse();
            }
            if debug[0].contains("://") {
                debug[0] = debug[0].rsplit("://").next().unwrap().to_string();
            }
            if debug[0].is_empty() || !debug[0].starts_with('/') {
                // Filter empty filenames as related entries cannot provide enough info
                // (e.g. "at func (:3:10)" cannot be attached to any source file)
                // Filter non-absolute paths as they are related to internal JS modules
                debug_info.file = "<anonymous>".to_string();
            } else {
                debug_info.file = debug[0].to_string();
            }
            if debug.len() == 1 {
                // Location contains filename only
                return Ok(debug_info);
            }

            debug_info.line = if let Ok(line) = debug[1].parse::<u64>() {
                line
            } else {
                return Err(Error::Casr(format!(
                    "Couldn't parse line number {}: {loc}",
                    debug[1]
                )));
            };
            if debug.len() == 3 {
                debug_info.column = if let Ok(column) = debug[2].parse::<u64>() {
                    column
                } else {
                    return Err(Error::Casr(format!(
                        "Couldn't parse column number {}: {loc}",
                        debug[2]
                    )));
                }
            }
            Ok(debug_info)
        }

        /// Parse substring of `entry` related to location in some file
        ///
        /// # Arguments
        ///
        /// * `entry` - initial string for stacktrace entry
        ///
        /// # Return value
        ///
        /// Parsed info about stacktrace entry
        fn parse_eval(entry: &str) -> Result<StacktraceEntry> {
            // at eval (eval at func [[as method]] (location), location2) |
            // at eval (eval at location, location2)
            let mut stentry = StacktraceEntry::default();
            let re = Regex::new(
                r"^\s*at eval \(eval at (?:(.+?) (?:(\[as.*?\]) )?\((.*?)\)|(.+?)), (.*?)\)$",
            )
            .unwrap();
            let Some(cap) = re.captures(entry) else {
                return Err(Error::Casr(format!(
                    "Couldn't parse stacktrace line: {entry}"
                )));
            };

            if let Some(function_name) = cap.get(1) {
                // at eval (eval at func [[as method]] (location), location2)
                let debug = function_name.as_str().to_string();
                stentry.function = if debug == "<anonymous>" {
                    // Eval is located in anonymous function
                    "eval".to_string()
                } else {
                    // Can append function name that eval is located in
                    "eval at ".to_string() + debug.as_str()
                };
                if let Some(method_name) = cap.get(2) {
                    // at eval (eval at func [as method] (location), location2)
                    stentry.function += (" ".to_string() + method_name.as_str()).as_str();
                }

                let debug = cap.get(3).unwrap().as_str().to_string();
                if debug.contains('(') || debug.contains(')') {
                    // location contains nested evals
                    // Fill <anonymous> to filter this entry from stacktrace
                    // after parsing
                    stentry.function = "<anonymous>".to_string();
                    return Ok(stentry);
                }
                stentry.debug = parse_location(&debug)?;
            } else if let Some(location) = cap.get(4) {
                // at eval (eval at location, location2)
                stentry.function = "eval".to_string();
                stentry.debug = parse_location(location.as_str())?;
            }

            // Recalculate location adding offset inside location2 in eval function
            let debug = cap.get(5).unwrap().as_str().to_string();
            let eval_debug = parse_location(&debug)?;
            if eval_debug.line >= 3 {
                // Line number inside eval function starts with 3
                stentry.debug.line += eval_debug.line - 3;
                if eval_debug.column != 0 {
                    stentry.debug.column = eval_debug.column;
                }
            }
            Ok(stentry)
        }

        if let Some(cap) = re_full.captures(entry) {
            if entry.starts_with("at eval") && entry.contains("eval at") {
                // at eval (eval at func [[as method]] (location), location2) |
                // at eval (eval at location, location2)
                // Parse eval
                stentry = parse_eval(entry)?;
            } else {
                // at func [[as method]] (location)
                // Parse function with location
                stentry.function = cap.get(1).unwrap().as_str().to_string();
                if let Some(method_name) = cap.get(2) {
                    // at func [as method] (location)
                    stentry.function += (" ".to_string() + method_name.as_str()).as_str();
                }
                let debug = cap.get(3).unwrap().as_str().to_string();
                stentry.debug = parse_location(&debug)?;
            }
        } else if let Some(cap) = re_without_pars.captures(entry) {
            // at location
            // Parse location only
            let debug = cap.get(1).unwrap().as_str().to_string();
            stentry.debug = parse_location(&debug)?;
        } else {
            return Err(Error::Casr(format!(
                "Couldn't parse stacktrace line: {entry}"
            )));
        }

        Ok(stentry)
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        entries
            .iter()
            .map(String::as_str)
            .filter(|entry| !entry.contains("unknown location"))
            .map(Self::parse_stacktrace_entry)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stacktrace::{CrashLineExt, Filter, tests::safe_init_ignore_stack_frames};

    #[test]
    fn test_js_stacktrace() {
        let stream = r#"Uncaught ReferenceError: var is not defined
    at new Uint8Array (<anonymous>)
    at Object.decode (/fuzz/node_modules/jpeg-js/lib/decoder.js:1110:13)
    at fuzz (/fuzz/FuzzTarget.js:6:14)
    at result (/fuzz/node_modules/fuzzer/core/core.ts:335:15)
    at Worker.fuzz [as fn] (/home/user/test_js_stacktrace/main.js:1:2017)
    at process.<anonymous> (/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/fuzzer/build/src/worker.js:55:30)
    at process.emit (node:events:527:28)
    at <anonymous>
    at bootstrap_node.js:609:3
    at file:///home/user/node/offset.js:3:37
    at fuzz (/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/jsfuzz/build/src/worker.js:55:30)
    at async Loader.import (internal/modules/esm/loader.js:178:24)
    at eval (eval at <anonymous> (eval at g (/fuzz/FuzzTarget.js:7:7)), <anonymous>:4:23)
    at eval (eval at <anonymous> (file:///home/user/node/offset.js:3:3), <anonymous>:3:7)
    at eval (eval at g (/fuzz/FuzzTarget.js:7:7), <anonymous>:8:13)
    at eval (/.svelte-kit/runtime/components/layout.svelte:8:41)
    at fuzz (/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/@jazzer.js/build/src/worker.js:55:30)
    at handler (:3:10)

Uncaught ReferenceError: var is not defined
    at Object.decode (/fuzz/node_modules/jpeg-js/lib/decoder.js:1110:13)
    at fuzz (/fuzz/FuzzTarget.js:6:14)
    at result (/fuzz/node_modules/fuzzer/core/core.ts:335:15)
    at Worker.fuzz [as fn] (/home/user/test_js_stacktrace/main.js:1:2017)
    at process.<anonymous> (/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/fuzzer/build/src/worker.js:55:30)
    at process.emit (node:events:527:28)
    at <anonymous>
    at bootstrap_node.js:609:3
    at file:///home/user/node/offset.js:3:37
    at fuzz (/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/jsfuzz/build/src/worker.js:55:30)
    at async Loader.import (internal/modules/esm/loader.js:178:24)
    at eval (eval at <anonymous> (eval at g (/fuzz/FuzzTarget.js:7:7)), <anonymous>:4:23)
    at eval (eval at <anonymous> (file:///home/user/node/offset.js:3:3), <anonymous>:3:7)
    at eval (eval at g (/fuzz/FuzzTarget.js:7:7), <anonymous>:8:13)
    at eval (/.svelte-kit/runtime/components/layout.svelte:8:41)
    at fuzz (/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/@jazzer.js/build/src/worker.js:55:30)
    at handler (:3:10)"#;

        let raw_stacktrace = &[
            "at new Uint8Array (<anonymous>)",
            "at Object.decode (/fuzz/node_modules/jpeg-js/lib/decoder.js:1110:13)",
            "at fuzz (/fuzz/FuzzTarget.js:6:14)",
            "at result (/fuzz/node_modules/fuzzer/core/core.ts:335:15)",
            "at Worker.fuzz [as fn] (/home/user/test_js_stacktrace/main.js:1:2017)",
            "at process.<anonymous> (/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/fuzzer/build/src/worker.js:55:30)",
            "at process.emit (node:events:527:28)",
            "at <anonymous>",
            "at bootstrap_node.js:609:3",
            "at file:///home/user/node/offset.js:3:37",
            "at fuzz (/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/jsfuzz/build/src/worker.js:55:30)",
            "at async Loader.import (internal/modules/esm/loader.js:178:24)",
            "at eval (eval at <anonymous> (eval at g (/fuzz/FuzzTarget.js:7:7)), <anonymous>:4:23)",
            "at eval (eval at <anonymous> (file:///home/user/node/offset.js:3:3), <anonymous>:3:7)",
            "at eval (eval at g (/fuzz/FuzzTarget.js:7:7), <anonymous>:8:13)",
            "at eval (/.svelte-kit/runtime/components/layout.svelte:8:41)",
            "at fuzz (/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/@jazzer.js/build/src/worker.js:55:30)",
            "at handler (:3:10)",
        ];

        let Some(exception) = JsException::parse_exception(stream) else {
            panic!("Couldn't get JS exception");
        };
        assert_eq!(exception.short_description, "ReferenceError");
        assert_eq!(exception.description, "var is not defined");

        let trace = raw_stacktrace
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();
        let bt = JsStacktrace::extract_stacktrace(stream).unwrap();
        assert_eq!(bt, trace);

        let sttr = JsStacktrace::parse_stacktrace(&bt);
        if sttr.is_err() {
            panic!("{}", sttr.err().unwrap());
        }
        let mut stacktrace = sttr.unwrap();

        safe_init_ignore_stack_frames();
        stacktrace.filter();

        // Check crashline
        let crash_line = stacktrace.crash_line();
        if let Ok(crash_line) = crash_line {
            assert_eq!(
                crash_line.to_string(),
                "/fuzz/node_modules/jpeg-js/lib/decoder.js:1110:13"
            );
        } else {
            panic!("{}", crash_line.err().unwrap());
        }

        assert_eq!(stacktrace.len(), 9);
        assert_eq!(
            stacktrace[0].debug.file,
            "/fuzz/node_modules/jpeg-js/lib/decoder.js".to_string()
        );
        assert_eq!(stacktrace[0].debug.line, 1110);
        assert_eq!(stacktrace[0].debug.column, 13);
        assert_eq!(stacktrace[0].function, "Object.decode".to_string());
        assert_eq!(stacktrace[1].debug.file, "/fuzz/FuzzTarget.js".to_string());
        assert_eq!(stacktrace[1].debug.line, 6);
        assert_eq!(stacktrace[1].debug.column, 14);
        assert_eq!(stacktrace[1].function, "fuzz".to_string());
        assert_eq!(
            stacktrace[2].debug.file,
            "/fuzz/node_modules/fuzzer/core/core.ts".to_string()
        );
        assert_eq!(stacktrace[2].debug.line, 335);
        assert_eq!(stacktrace[2].debug.column, 15);
        assert_eq!(stacktrace[2].function, "result".to_string());
        assert_eq!(
            stacktrace[3].debug.file,
            "/home/user/test_js_stacktrace/main.js".to_string()
        );
        assert_eq!(stacktrace[3].debug.line, 1);
        assert_eq!(stacktrace[3].debug.column, 2017);
        assert_eq!(stacktrace[3].function, "Worker.fuzz [as fn]".to_string());
        assert_eq!(
            stacktrace[4].debug.file,
            "/home/user/.nvm/versions/node/v16.15.1/lib/node_modules/fuzzer/build/src/worker.js"
                .to_string()
        );
        assert_eq!(stacktrace[4].debug.line, 55);
        assert_eq!(stacktrace[4].debug.column, 30);
        assert_eq!(stacktrace[4].function, "process.<anonymous>".to_string());
        assert_eq!(
            stacktrace[5].debug.file,
            "/home/user/node/offset.js".to_string()
        );
        assert_eq!(stacktrace[5].debug.line, 3);
        assert_eq!(stacktrace[5].debug.column, 37);
        assert_eq!(stacktrace[5].function, "".to_string());
        assert_eq!(
            stacktrace[6].debug.file,
            "/home/user/node/offset.js".to_string()
        );
        assert_eq!(stacktrace[6].debug.line, 3);
        assert_eq!(stacktrace[6].debug.column, 7);
        assert_eq!(stacktrace[6].function, "eval".to_string());
        assert_eq!(stacktrace[7].debug.file, "/fuzz/FuzzTarget.js".to_string());
        assert_eq!(stacktrace[7].debug.line, 12);
        assert_eq!(stacktrace[7].debug.column, 13);
        assert_eq!(stacktrace[7].function, "eval at g".to_string());
        assert_eq!(
            stacktrace[8].debug.file,
            "/.svelte-kit/runtime/components/layout.svelte".to_string()
        );
        assert_eq!(stacktrace[8].debug.line, 8);
        assert_eq!(stacktrace[8].debug.column, 41);
        assert_eq!(stacktrace[8].function, "eval".to_string());
    }
}
