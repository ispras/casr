//! JS module implements `ParseStacktrace` and `Exception` traits for JS reports.
use crate::stacktrace::ParseStacktrace;

use crate::error::*;
use crate::stacktrace::*;
use regex::Regex;

/// Structure provides an interface for processing the stack trace.
pub struct JSStacktrace;

impl ParseStacktrace for JSStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        // Get stack trace from JS report.
        let re =
            Regex::new(r"(?m)^(?:.*Error)(?:.|\n)*?((?:\n(?:\s|\t)+at .*(?:\(.*\))?)+)").unwrap();
        let Some(cap) = re.captures(stream) else {
            return Err(Error::Casr(
                "Couldn't find traceback in JS report".to_string(),
            ));
        };
        let stacktrace = cap
            .get(1)
            .unwrap()
            .as_str()
            .split('\n')
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect::<Vec<String>>();

        Ok(stacktrace)
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let mut stentry = StacktraceEntry::default();
        let re_full = Regex::new(
            r"^(?:\s|\t)*at(?:\s|\t)+(.+?)(?:(?:\s|\t)+(\[as.*?\])?(?:\s|\t)*)\((.*)\)$",
        )
        .unwrap();
        let re_without_pars =
            Regex::new(r"^(?:\s|\t)*at(?:\s|\t)+(.+?)(?:(?:(?:\s|\t)+(\[as.*?\]))?(?:\s|\t)*)$")
                .unwrap();

        fn parse_location(
            entry: &str,
            stentry: &mut StacktraceEntry,
            loc: &str,
            can_be_func: bool,
        ) -> Result<()> {
            let mut debug: Vec<String> = loc.split(':').map(|s| s.to_string()).collect();
            if debug.len() > 1 {
                if debug.len() > 3 {
                    let tail = debug[debug.len() - 2..].to_vec();
                    debug = [debug[..debug.len() - 2].join(":")].to_vec();
                    debug.append(&mut tail.to_vec());
                }
                stentry.debug.file = debug[0].to_string();
                stentry.debug.line = if let Ok(line) = debug[1].parse::<u64>() {
                    line
                } else {
                    return Err(Error::Casr(format!(
                        "Couldn't parse line number {}. Entry: {entry}",
                        debug[1]
                    )));
                };
                if debug.len() == 3 {
                    stentry.debug.column = if let Ok(column) = debug[2].parse::<u64>() {
                        column
                    } else {
                        return Err(Error::Casr(format!(
                            "Couldn't parse column number {}. Entry: {entry}",
                            debug[2]
                        )));
                    }
                }
            } else if can_be_func {
                if debug[0].ends_with(".js") || debug[0] == "native" {
                    stentry.debug.file = debug[0].to_string();
                } else {
                    stentry.function = debug[0].to_string();
                }
            } else {
                stentry.debug.file = debug[0].to_string();
            }
            Ok(())
        }

        fn parse_eval(entry: &str, stentry: &mut StacktraceEntry) -> Result<()> {
            let re = Regex::new(
                r"^(?:\s|\t)*at(?:\s|\t)+eval(?:\s|\t)+\((?:eval(?:\s|\t)+at(?:\s|\t)+(.*?)(?:\s|\t)+(?:(\[as.*?\])(?:\s|\t)+)?)(?:\((.*)\))(?:,(?:\s|\t)+(.*))\)$",
            )
            .unwrap();
            let Some(cap) = re.captures(entry) else {
                return Err(Error::Casr(format!(
                    "Couldn't parse stacktrace line: {entry}"
                )));
            };

            let debug = cap.get(1).unwrap().as_str().to_string();
            if debug == "<anonymous>" {
                stentry.function = "eval".to_string();
            } else {
                stentry.function = "eval at ".to_string() + debug.as_str();
            }
            if let Some(method_name) = cap.get(2) {
                stentry.function += (" ".to_string() + method_name.as_str()).as_str();
            }

            let debug = cap.get(3).unwrap().as_str().to_string();
            if debug.contains('(') || debug.contains(')') {
                // Irrelevant entry that contains nested evals
                // Fill <anonymous> to filter this ectry from stacktrace
                // after parsing
                stentry.function = "<anonymous>".to_string();
                return Ok(());
            }
            parse_location(entry, stentry, &debug, false)?;

            let debug = cap.get(4).unwrap().as_str().to_string();
            let mut eval_stentry = StacktraceEntry::default();
            parse_location(entry, &mut eval_stentry, &debug, false)?;
            if eval_stentry.debug.line != 0 {
                stentry.debug.line += eval_stentry.debug.line - 3;
                if eval_stentry.debug.column != 0 {
                    stentry.debug.column = eval_stentry.debug.column;
                }
            }
            Ok(())
        }

        if let Some(cap) = re_full.captures(entry) {
            if entry.starts_with("at eval") && entry.contains("eval at") {
                // Parse eval
                parse_eval(entry, &mut stentry)?;
            } else {
                // at function ([file][:line[:column]])
                // Not eval
                stentry.function = cap.get(1).unwrap().as_str().to_string();
                if let Some(method_name) = cap.get(2) {
                    stentry.function += (" ".to_string() + method_name.as_str()).as_str();
                }
                let debug = cap.get(3).unwrap().as_str().to_string();
                parse_location(entry, &mut stentry, &debug, false)?;
            }
        } else if let Some(cap) = re_without_pars.captures(entry) {
            let debug = cap.get(1).unwrap().as_str().to_string();
            parse_location(entry, &mut stentry, &debug, true)?;
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
            .filter(|entry| {
                entry.as_ref().is_ok_and(|x| {
                    x.debug.file != "native"
                        && x.debug.file != "<anonymous>"
                        && x.function != "<anonymous>"
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_js_stacktrace() {
        let raw_stacktrace = &[
            "at new Uint8Array (<anonymous>)",
            "at Object.decode (/fuzz/node_modules/jpeg-js/lib/decoder.js:1110:13)",
            "at fuzz (/fuzz/FuzzTarget.js:6:14)",
            "at result (/fuzz/node_modules/@jazzer.js/core/core.ts:335:15)",
            "at Worker.fuzz [as fn] (/home/pa_darochek/Documents/SandBox/test_js_stacktrace/main.js:1:2017)",
            "at process.<anonymous> (/home/pa_darochek/.nvm/versions/node/v16.15.1/lib/node_modules/jsfuzz/build/src/worker.js:55:30)",
            "at process.emit (node:events:527:28)",
            "at func (:1:2)",
            "at <anonymous>",
            "at bootstrap_node.js:609:3",
            "at file://<path-to-parent-folder>/offset.js:3:37",
            "at async Loader.import (internal/modules/esm/loader.js:178:24)",
            "at eval (eval at <anonymous> (eval at g (/fuzz/FuzzTarget.js:7:7)), <anonymous>:4:23)",
            "at eval (eval at <anonymous> (file://<path-to-parent-folder>/offset.js:3:3), <anonymous>:3:7)",
            "at eval (eval at g (/fuzz/FuzzTarget.js:7:7), <anonymous>:8:13)",
            "at eval (/.svelte-kit/runtime/components/layout.svelte:8:41)",
        ];
        let trace = raw_stacktrace
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();
        let sttr = JSStacktrace::parse_stacktrace(&trace);
        if sttr.is_err() {
            panic!("{}", sttr.err().unwrap());
        }

        let stacktrace = sttr.unwrap();
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
            "/fuzz/node_modules/@jazzer.js/core/core.ts".to_string()
        );
        assert_eq!(stacktrace[2].debug.line, 335);
        assert_eq!(stacktrace[2].debug.column, 15);
        assert_eq!(stacktrace[2].function, "result".to_string());
        assert_eq!(
            stacktrace[3].debug.file,
            "/home/pa_darochek/Documents/SandBox/test_js_stacktrace/main.js".to_string()
        );
        assert_eq!(stacktrace[3].debug.line, 1);
        assert_eq!(stacktrace[3].debug.column, 2017);
        assert_eq!(stacktrace[3].function, "Worker.fuzz [as fn]".to_string());
        assert_eq!(stacktrace[4].debug.file, "/home/pa_darochek/.nvm/versions/node/v16.15.1/lib/node_modules/jsfuzz/build/src/worker.js".to_string());
        assert_eq!(stacktrace[4].debug.line, 55);
        assert_eq!(stacktrace[4].debug.column, 30);
        assert_eq!(stacktrace[4].function, "process.<anonymous>".to_string());
        assert_eq!(stacktrace[5].debug.file, "node:events".to_string());
        assert_eq!(stacktrace[5].debug.line, 527);
        assert_eq!(stacktrace[5].debug.column, 28);
        assert_eq!(stacktrace[5].function, "process.emit".to_string());
        assert_eq!(stacktrace[6].debug.file, "".to_string());
        assert_eq!(stacktrace[6].debug.line, 1);
        assert_eq!(stacktrace[6].debug.column, 2);
        assert_eq!(stacktrace[6].function, "func".to_string());
        assert_eq!(stacktrace[7].debug.file, "bootstrap_node.js".to_string());
        assert_eq!(stacktrace[7].debug.line, 609);
        assert_eq!(stacktrace[7].debug.column, 3);
        assert_eq!(stacktrace[7].function, "".to_string());
        assert_eq!(
            stacktrace[8].debug.file,
            "file://<path-to-parent-folder>/offset.js".to_string()
        );
        assert_eq!(stacktrace[8].debug.line, 3);
        assert_eq!(stacktrace[8].debug.column, 37);
        assert_eq!(stacktrace[8].function, "".to_string());
        assert_eq!(
            stacktrace[9].debug.file,
            "internal/modules/esm/loader.js".to_string()
        );
        assert_eq!(stacktrace[9].debug.line, 178);
        assert_eq!(stacktrace[9].debug.column, 24);
        assert_eq!(stacktrace[9].function, "async Loader.import".to_string());
        assert_eq!(
            stacktrace[10].debug.file,
            "file://<path-to-parent-folder>/offset.js".to_string()
        );
        assert_eq!(stacktrace[10].debug.line, 3);
        assert_eq!(stacktrace[10].debug.column, 7);
        assert_eq!(stacktrace[10].function, "eval".to_string());
        assert_eq!(stacktrace[11].debug.file, "/fuzz/FuzzTarget.js".to_string());
        assert_eq!(stacktrace[11].debug.line, 12);
        assert_eq!(stacktrace[11].debug.column, 13);
        assert_eq!(stacktrace[11].function, "eval at g".to_string());
        assert_eq!(
            stacktrace[12].debug.file,
            "/.svelte-kit/runtime/components/layout.svelte".to_string()
        );
        assert_eq!(stacktrace[12].debug.line, 8);
        assert_eq!(stacktrace[12].debug.column, 41);
        assert_eq!(stacktrace[12].function, "eval".to_string());
    }
}
