//! Java module implements `ParseStacktrace` and `Exception` traits for Java reports.
use crate::error::*;
use crate::exception::Exception;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::ParseStacktrace;
use crate::stacktrace::*;

use regex::Regex;

/// Structure provides an interface for processing the stack trace.
pub struct JavaStacktrace;

impl ParseStacktrace for JavaStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        /// Structure represents the Java stack trace exception block.
        struct JavaExceptionBlock<'a> {
            /// Vector of stack trace entries.
            body: Vec<&'a str>,
            /// Number of convolute frames.
            conv_counter: usize,
        }
        // Get java stack trace.
        let re = Regex::new(r"(?m)^(?:Caused by:|Exception in thread|== Java Exception:)(?:.|\n)*?((?:\n(?:\s|\t)+at .*\(.*\))+)(?:\n(?:\s|\t)+\.\.\. (\d+) more)?").unwrap();
        let mut blocks = Vec::new();
        for cap in re.captures_iter(stream) {
            let body: Vec<&'_ str> = cap
                .get(1)
                .unwrap()
                .as_str()
                .split('\n')
                .filter(|x| !x.is_empty())
                .rev()
                .collect();
            let conv_counter = cap
                .get(2)
                .map(|number| number.as_str().parse::<usize>().unwrap())
                .unwrap_or_default();
            blocks.push(JavaExceptionBlock { body, conv_counter });
        }
        let Some(last_block) = blocks.last() else {
            return Err(Error::Casr("Couldn't find stacktrace".to_string()));
        };
        let mut prev_num = last_block.conv_counter;
        let mut forward_stacktrace = last_block.body.iter().rev().copied().collect::<Vec<&str>>();

        for block in blocks.iter().rev() {
            let cur_num = block.conv_counter;
            let diff = prev_num - cur_num;
            forward_stacktrace.extend_from_slice(
                &block.body[..diff]
                    .iter()
                    .rev()
                    .copied()
                    .collect::<Vec<&str>>(),
            );
            prev_num = cur_num;
            if cur_num == 0 {
                break;
            }
        }
        if forward_stacktrace.is_empty() {
            return Err(Error::Casr("Empty stacktrace.".to_string()));
        }

        Ok(forward_stacktrace.iter().map(|x| x.to_string()).collect())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let re = Regex::new(r"(?:\s|\t)*at (.*)\((.*)\)").unwrap();

        let Some(cap) = re.captures(entry) else {
            return Err(Error::Casr(format!(
                "Couldn't parse stacktrace line: {entry}"
            )));
        };
        let debug = cap.get(2).unwrap().as_str().to_string();
        let mut stentry = StacktraceEntry::default();
        let debug: Vec<&str> = debug.split(':').collect();
        stentry.debug.file = debug[0].to_string();
        if debug.len() > 1 {
            stentry.debug.line = if let Ok(line) = debug[1].parse::<u64>() {
                line
            } else {
                return Err(Error::Casr(format!(
                    "Couldn't parse line number {}. Entry: {entry}",
                    debug[1]
                )));
            };
        }
        stentry.function = cap.get(1).unwrap().as_str().to_string();

        Ok(stentry)
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        entries
            .iter()
            .map(String::as_str)
            .filter(|entry| !entry.contains("Unknown Source") && !entry.contains("Native Method"))
            .map(Self::parse_stacktrace_entry)
            .collect()
    }
}

/// Structure provides an interface for parsing java exception message.
pub struct JavaException;

impl Exception for JavaException {
    fn parse_exception(description: &str) -> Option<ExecutionClass> {
        let description = description.split_inclusive('\n').rev().collect::<String>();
        let re = Regex::new(
            r"(?:Caused by: |Exception in thread .*? |== Java Exception: )(?:(\S+?): )?(.+)",
        )
        .unwrap();
        re.captures(&description).map(|cap| {
            ExecutionClass::new((
                "NOT_EXPLOITABLE",
                if let Some(class) = cap.get(1) {
                    class.as_str()
                } else {
                    cap.get(2).unwrap().as_str()
                },
                if cap.get(1).is_some() {
                    cap.get(2).unwrap().as_str()
                } else {
                    ""
                },
                "",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_java_stacktrace() {
        let raw_stacktrace = &[
           "at java.base/jdk.internal.loader.NativeLibraries.load(Native Method)",
           "at java.base/jdk.internal.loader.NativeLibraries$NativeLibraryImpl.open(NativeLibraries.java:388)",
           "at java.base/jdk.internal.loader.NativeLibraries.loadLibrary(NativeLibraries.java:232)",
           "at java.base/jdk.internal.loader.NativeLibraries.loadLibrary(NativeLibraries.java:174)",
           "at java.base/jdk.internal.loader.NativeLibraries.findFromPaths(NativeLibraries.java:315)",
           "at java.base/jdk.internal.loader.NativeLibraries.loadLibrary(NativeLibraries.java:287)",
           "at java.base/java.lang.ClassLoader.loadLibrary(ClassLoader.java:2422)",
           "at java.base/java.lang.Runtime.loadLibrary0(Runtime.java:818)",
           "at java.base/java.lang.System.loadLibrary(System.java:1989)",
           "at ExampleFuzzerNative.<clinit>(ExampleFuzzerNative.java:20)",
           "at java.base/java.lang.Class.forName0(Native Method)",
           "at java.base/java.lang.Class.forName(Class.java)",
           "at Reproducer.main(Reproducer.java:24)",
        ];
        let trace = raw_stacktrace
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();
        let sttr = JavaStacktrace::parse_stacktrace(&trace);
        if sttr.is_err() {
            panic!("{}", sttr.err().unwrap());
        }

        let stacktrace = sttr.unwrap();
        assert_eq!(stacktrace[0].debug.file, "NativeLibraries.java".to_string());
        assert_eq!(stacktrace[0].debug.line, 388);
        assert_eq!(
            stacktrace[0].function,
            "java.base/jdk.internal.loader.NativeLibraries$NativeLibraryImpl.open".to_string()
        );
        assert_eq!(stacktrace[1].debug.file, "NativeLibraries.java".to_string());
        assert_eq!(stacktrace[1].debug.line, 232);
        assert_eq!(
            stacktrace[1].function,
            "java.base/jdk.internal.loader.NativeLibraries.loadLibrary".to_string()
        );
        assert_eq!(stacktrace[2].debug.file, "NativeLibraries.java".to_string());
        assert_eq!(stacktrace[2].debug.line, 174);
        assert_eq!(
            stacktrace[2].function,
            "java.base/jdk.internal.loader.NativeLibraries.loadLibrary".to_string()
        );
        assert_eq!(stacktrace[3].debug.file, "NativeLibraries.java".to_string());
        assert_eq!(stacktrace[3].debug.line, 315);
        assert_eq!(
            stacktrace[3].function,
            "java.base/jdk.internal.loader.NativeLibraries.findFromPaths".to_string()
        );
        assert_eq!(stacktrace[4].debug.file, "NativeLibraries.java".to_string());
        assert_eq!(stacktrace[4].debug.line, 287);
        assert_eq!(
            stacktrace[4].function,
            "java.base/jdk.internal.loader.NativeLibraries.loadLibrary".to_string()
        );
        assert_eq!(stacktrace[5].debug.file, "ClassLoader.java".to_string());
        assert_eq!(stacktrace[5].debug.line, 2422);
        assert_eq!(
            stacktrace[5].function,
            "java.base/java.lang.ClassLoader.loadLibrary".to_string()
        );
        assert_eq!(stacktrace[6].debug.file, "Runtime.java".to_string());
        assert_eq!(stacktrace[6].debug.line, 818);
        assert_eq!(
            stacktrace[6].function,
            "java.base/java.lang.Runtime.loadLibrary0".to_string()
        );
        assert_eq!(stacktrace[7].debug.file, "System.java".to_string());
        assert_eq!(stacktrace[7].debug.line, 1989);
        assert_eq!(
            stacktrace[7].function,
            "java.base/java.lang.System.loadLibrary".to_string()
        );
        assert_eq!(
            stacktrace[8].debug.file,
            "ExampleFuzzerNative.java".to_string()
        );
        assert_eq!(stacktrace[8].debug.line, 20);
        assert_eq!(
            stacktrace[8].function,
            "ExampleFuzzerNative.<clinit>".to_string()
        );
        assert_eq!(stacktrace[9].debug.file, "Class.java".to_string());
        assert_eq!(stacktrace[9].debug.line, 0);
        assert_eq!(
            stacktrace[9].function,
            "java.base/java.lang.Class.forName".to_string()
        );
        assert_eq!(stacktrace[10].debug.file, "Reproducer.java".to_string());
        assert_eq!(stacktrace[10].debug.line, 24);
        assert_eq!(stacktrace[10].function, "Reproducer.main".to_string());
    }
}
