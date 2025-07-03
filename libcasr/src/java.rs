//! Java module implements `ParseStacktrace` and `Exception` traits for Java reports.
use regex::Regex;

use crate::{
    error::{Error, Result},
    exception::Exception,
    execution_class::ExecutionClass,
    report::ReportExtractor,
    stacktrace::{CrashLine, ParseStacktrace, Stacktrace, StacktraceContext, StacktraceEntry},
};

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
        let re = Regex::new(r"(?m)^(?:Caused by:|Exception in thread|== Java Exception:)(?:.|\n)*?((?:\n\s*at .*\(.*\))+)(?:\n\s*\.\.\. (\d+) more)?").unwrap();
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

        Ok(forward_stacktrace
            .iter()
            .map(|x| x.trim().to_string())
            .collect())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let re = Regex::new(r"\s*at (.*)\((.*)\)").unwrap();

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
pub struct JavaException {
    context: StacktraceContext,
}

impl JavaException {
    /// Create new `JavaException` instance from stream
    pub fn new(stream: &str) -> Result<Option<Self>> {
        let stream: Vec<String> = stream.split('\n').map(|l| l.trim().to_string()).collect();
        let re = Regex::new(r"Exception in thread .*? |== Java Exception: ").unwrap();
        let Some(start) = stream.iter().position(|l| re.is_match(l)) else {
            return Ok(None::<Self>);
        };
        let mut report = stream[start..].to_vec();
        if let Some(end) = report
            .iter()
            .rposition(|l| l.starts_with("== libFuzzer crashing input =="))
        {
            report.drain(end..);
        }
        report.retain(|l| !l.is_empty());
        Ok(Some(Self {
            context: StacktraceContext::new(report.join("\n"), None),
        }))
    }
}

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

impl ReportExtractor for JavaException {
    fn extract_stacktrace(&mut self) -> Result<Vec<String>> {
        self.context.extract_stacktrace::<JavaStacktrace>()
    }
    fn parse_stacktrace(&mut self) -> Result<Stacktrace> {
        self.context.parse_stacktrace::<JavaStacktrace>()
    }
    fn crash_line(&mut self) -> Result<CrashLine> {
        self.context.crash_line::<JavaStacktrace>()
    }
    fn stream(&self) -> &str {
        self.context.stream()
    }
    fn report(&self) -> Vec<String> {
        self.context.report()
    }
    fn execution_class(&self) -> Result<ExecutionClass> {
        let Some(class) = JavaException::parse_exception(self.context.stream()) else {
            return Err(Error::Casr("Java exception is not found!".to_string()));
        };
        Ok(class)
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

    #[test]
    fn test_java_extractor() {
        let stream = "
            Exception in thread \"main\" HighLevelException: MidLevelException: LowLevelException
                at Test1.a(Test1.java:16)
                at Test1.ma(Test1.java:10)
                at Test1.main(Test1.java:4)
            Caused by: MidLevelException: LowLevelException
                at Test1.f(Test1.java:37)
                at Test1.c(Test1.java:26)
                at Test1.b(Test1.java:20)
                at Test1.a(Test1.java:14)
                at Test1.ma(Test1.java:10)
                at Test1.main(Test1.java:4)
                at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
                at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:77)
                at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
                at java.base/java.lang.reflect.Method.invoke(Method.java:569)
                at jdk.compiler/com.sun.tools.javac.launcher.Main.execute(Main.java:419)
                at jdk.compiler/com.sun.tools.javac.launcher.Main.run(Main.java:192)
                at jdk.compiler/com.sun.tools.javac.launcher.Main.main(Main.java:132)
            Caused by: LowLevelException
                at Test1.e(Test1.java:33)
                at Test1.d(Test1.java:30)
                at Test1.c(Test1.java:24)
                ... 11 more
                Suppressed: MidLevelException: LowLevelException
                    at Test1.f(Test1.java:36)
                    at Test1.c(Test1.java:26)
                    ... 11 more
                Caused by: LowLevelException
                    ... 13 more";

        let Ok(Some(mut exception)) = JavaException::new(stream) else {
            panic!("Can't extract Java exception");
        };

        let lines = exception.report();
        assert_eq!(lines.len(), 29);

        let sttr = exception.extract_stacktrace();
        let Ok(sttr) = sttr else {
            panic!("{}", sttr.err().unwrap());
        };
        assert_eq!(sttr.len(), 14);

        let sttr = ReportExtractor::parse_stacktrace(&mut exception);
        let Ok(sttr) = sttr else {
            panic!("{}", sttr.err().unwrap());
        };
        assert_eq!(sttr.len(), 13);

        assert_eq!(sttr[0].debug.file, "Test1.java".to_string());
        assert_eq!(sttr[0].debug.line, 33);
        assert_eq!(sttr[0].function, "Test1.e".to_string());

        assert_eq!(sttr[1].debug.file, "Test1.java".to_string());
        assert_eq!(sttr[1].debug.line, 30);
        assert_eq!(sttr[1].function, "Test1.d".to_string());

        assert_eq!(sttr[2].debug.file, "Test1.java".to_string());
        assert_eq!(sttr[2].debug.line, 24);
        assert_eq!(sttr[2].function, "Test1.c".to_string());

        let crashline = exception.crash_line();
        let Ok(crashline) = crashline else {
            panic!("{}", crashline.err().unwrap());
        };
        assert_eq!(crashline.to_string(), "Test1.java:33",);

        let execution_class = exception.execution_class();
        let Ok(execution_class) = execution_class else {
            panic!(
                "Execution class is corrupted: {}",
                execution_class.err().unwrap()
            );
        };
        assert_eq!(execution_class.severity, "NOT_EXPLOITABLE");
        assert_eq!(execution_class.short_description, "LowLevelException");
        assert_eq!(execution_class.description, "");
        assert_eq!(execution_class.explanation, "");
    }
}
