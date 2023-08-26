//! UndefinedBehaviorSanitizer module implements `Severity` and `CrashLineExt` traits for UndefinedBehaviorSanitizer warnings.
use crate::asan::AsanStacktrace;
use crate::severity::Severity;
use crate::stacktrace::{CrashLine, CrashLineExt, DebugInfo};
use crate::stacktrace::{ParseStacktrace, Stacktrace, StacktraceEntry};

use crate::error::*;
use crate::execution_class::ExecutionClass;
use regex::Regex;

/// Structure provides an interface for parsing ubsan runtime error message.
#[derive(Clone, Debug)]
pub struct UbsanWarning {
    pub message: String,
}

impl UbsanWarning {
    /// Extract stack trace from ubsan message.
    pub fn extract_stacktrace(&self) -> Result<Vec<String>> {
        AsanStacktrace::extract_stacktrace(&self.message)
    }
    /// Transform stack trace line into StacktraceEntry type.
    pub fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        AsanStacktrace::parse_stacktrace_entry(entry)
    }
    /// Transform stack trace strings into Stacktrace type.
    pub fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        AsanStacktrace::parse_stacktrace(entries)
    }
    /// Get ubsan runtime error message as a vector of lines.
    pub fn ubsan_report(&self) -> Vec<String> {
        self.message
            .split('\n')
            .map(|s| s.trim_end().to_string())
            .collect()
    }
}

impl Severity for UbsanWarning {
    fn severity(&self) -> Result<ExecutionClass> {
        let message = self.ubsan_report();
        if message.len() <= 1 {
            return Err(Error::Casr("Malformed ubsan message".to_string()));
        }
        // Get description (from first line)
        let description = message.first().unwrap();
        let re = Regex::new(r#".+: runtime error: (.+)"#).unwrap();
        let Some(cap) = re.captures(description) else {
            return Err(Error::Casr(format!(
                "Couldn't parse error description: {description}"
            )));
        };
        let description = cap.get(1).unwrap().as_str().to_string();
        // Get short description (from last line)
        let short_description = message.last().unwrap();
        let re = Regex::new(r#"SUMMARY: UndefinedBehaviorSanitizer: (\S+)"#).unwrap();
        let Some(cap) = re.captures(short_description) else {
            return Err(Error::Casr(format!(
                "Couldn't parse ubsan summary: {short_description}"
            )));
        };
        let short_description = cap.get(1).unwrap().as_str().to_string();

        Ok(ExecutionClass::new((
            "NOT_EXPLOITABLE",
            &short_description,
            &description,
            "",
        )))
    }
}

impl CrashLineExt for UbsanWarning {
    fn crash_line(&self) -> Result<CrashLine> {
        let message = self.ubsan_report();
        if message.is_empty() {
            return Err(Error::Casr("Empty ubsan message".to_string()));
        }
        // If there is no stacktrace use crashline from first string
        // May be not absolute
        // Else use first string from stacktrace
        let crashline = if let Some(crashline) = message
            .iter()
            .skip(1)
            .find(|line| line.starts_with("    #0 "))
        {
            crashline
        } else {
            &message[0]
        };

        if let Ok(crashline) = UbsanWarning::parse_stacktrace_entry(crashline) {
            if !crashline.debug.file.is_empty() {
                Ok(CrashLine::Source(crashline.debug))
            } else if !crashline.module.is_empty() && crashline.offset != 0 {
                Ok(CrashLine::Module {
                    file: crashline.module,
                    offset: crashline.offset,
                })
            } else {
                Err(Error::Casr(format!(
                    "Couldn't collect crashline from stack trace: {:?}",
                    crashline
                )))
            }
        } else {
            let re = Regex::new(r#"(.+?):(\d+):(?:(\d+):)? runtime error: "#).unwrap();
            let Some(cap) = re.captures(crashline) else {
                return Err(Error::Casr(format!(
                    "Couldn't parse error crashline: {crashline}"
                )));
            };
            let file = cap.get(1).unwrap().as_str().to_string();
            let line = cap.get(2).unwrap().as_str().parse::<u64>();
            let Ok(line) = line else {
                return Err(Error::Casr(format!(
                    "Couldn't parse crashline line: {crashline}"
                )));
            };
            if let Some(column) = cap.get(3) {
                let column = column.as_str().parse::<u64>();
                let Ok(column) = column else {
                    return Err(Error::Casr(format!(
                        "Couldn't parse crashline column: {crashline}"
                    )));
                };
                return Ok(CrashLine::Source(DebugInfo { file, line, column }));
            }
            Ok(CrashLine::Source(DebugInfo {
                file,
                line,
                column: 0,
            }))
        }
    }
}

/// Extract ubsan warnings form stderr
///
/// # Arguments
///
/// * `stderr` - output containing ubsan warnings
///
/// # Return value
///
/// Ubsan warning struct vector
///
pub fn extract_ubsan_warnings(stderr: &str) -> Vec<UbsanWarning> {
    let mut ubsan_warnings: Vec<UbsanWarning> = vec![];
    let re =
        Regex::new(r#"(.+: runtime error: (?:.*\n)*?SUMMARY: UndefinedBehaviorSanitizer: .*)"#)
            .unwrap();
    for cap in re.captures_iter(stderr) {
        let message = cap[0].to_string();
        ubsan_warnings.push(UbsanWarning { message });
    }
    ubsan_warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubsan_parse() {
        let stderr =
            "/tarantool/src/box/sql/build.c:263:17: runtime error: null pointer passed as argument 2, which is declared to never be null
/usr/include/string.h:44:28: note: nonnull attribute specified here
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /tarantool/src/box/sql/build.c:263:17 in
/tarantool/src/box/sql/vdbeaux.c:1417:6: runtime error: implicit conversion from type 'int' of value -8 (32-bit, signed) to type 'unsigned long' changed the value to 18446744073709551608 (64-bit, unsigned)
    #0 0x14529af in sqlVdbeMakeReady /tarantool/src/box/sql/vdbeaux.c:1417:6
    #1 0xd94ff7 in sql_finish_coding /tarantool/src/box/sql/build.c:109:3
    #2 0x1291e28 in sql_code_ast /tarantool/src/box/sql/tokenize.c:506:3
    #3 0x128f24c in sqlRunParser /tarantool/src/box/sql/tokenize.c:585:2
    #4 0x10d6e5b in sql_stmt_compile /tarantool/src/box/sql/prepare.c:79:4
    #5 0xd01caf in sql_fuzz /tarantool/src/box/sql.c:1730:6
    #6 0x8ced0e in TestOneProtoInput(sql_query::SQLQuery const&) /tarantool/test/fuzz/sql_fuzzer/sql_fuzzer.cc:50:2
    #7 0x8ce0d9 in LLVMFuzzerTestOneInput /tarantool/test/fuzz/sql_fuzzer/sql_fuzzer.cc:38:1
    #8 0x7f4131 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project-llvmorg-14.0.6/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #9 0x7de03c in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /llvm-project-llvmorg-14.0.6/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:324:6
    #10 0x7e3d8b in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /llvm-project-llvmorg-14.0.6/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:860:9
    #11 0x80d342 in main /llvm-project-llvmorg-14.0.6/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #12 0x7f296f4d7082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 1878e6b475720c7c51969e69ab2d276fae6d1dee)
    #13 0x7d895d in _start (/sql_fuzzer+0x7d895d)

SUMMARY: UndefinedBehaviorSanitizer: implicit-integer-sign-change /tarantool/src/box/sql/vdbeaux.c:1417:6 in
Executed sql-out/corpus/7daf7545bad605f9ea192f6523d5427c757e56a4 in 66 ms
***
*** NOTE: fuzzing was not performed, you have only
***       executed the target code on a fixed set of inputs.
***
/tarantool/src/lib/small/include/small/lf_lifo.h:86:59: runtime error: applying non-zero offset 1 to null pointer
    #0 0x3f6a87e in lf_lifo_push /tarantool/src/lib/small/include/small/lf_lifo.h:86:59
    #1 0x3f6a162 in slab_unmap /tarantool/src/lib/small/small/slab_arena.c:275:2
    #2 0x3ebb1da in slab_cache_destroy /tarantool/src/lib/small/small/slab_cache.c:213:4
    #3 0x3c1773d in cord_destroy /tarantool/src/lib/core/fiber.c:1704:2
    #4 0x3c26a42 in fiber_free /tarantool/src/lib/core/fiber.c:2040:2
    #5 0x8cd6fa in teardown() /tarantool/test/fuzz/sql_fuzzer/sql_fuzzer.cc:34:2
    #6 0x7f296fe8df6a  (/lib64/ld-linux-x86-64.so.2+0x11f6a) (BuildId: 4587364908de169dec62ffa538170118c1c3a078)
    #7 0x7f296f4f98a6  (/lib/x86_64-linux-gnu/libc.so.6+0x468a6) (BuildId: 1878e6b475720c7c51969e69ab2d276fae6d1dee)
    #8 0x7f296f4f9a5f in exit (/lib/x86_64-linux-gnu/libc.so.6+0x46a5f) (BuildId: 1878e6b475720c7c51969e69ab2d276fae6d1dee)
    #9 0x7e3f43 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /llvm-project-llvmorg-14.0.6/compiler-rt/lib/fuzzer/FuzzerDriver.cpp
    #10 0x80d342 in main /llvm-project-llvmorg-14.0.6/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #11 0x7f296f4d7082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 1878e6b475720c7c51969e69ab2d276fae6d1dee)
    #12 0x7d895d in _start (/sql_fuzzer+0x7d895d)

SUMMARY: UndefinedBehaviorSanitizer: nullptr-with-nonzero-offset /tarantool/src/lib/small/include/small/lf_lifo.h:86:59 in";
        // Check warning extract
        let warnings = extract_ubsan_warnings(stderr);
        assert_eq!(warnings.len(), 3, "{:?}", warnings);

        // Check warning
        let warning = &warnings[0];
        assert_eq!(warning.ubsan_report().len(), 3);

        // Check severity
        let execution_class = warning.severity();
        let Ok(execution_class) = execution_class else {
            panic!("{}", execution_class.err().unwrap());
        };
        assert_eq!(execution_class.severity, "NOT_EXPLOITABLE");
        assert_eq!(execution_class.short_description, "undefined-behavior");
        assert_eq!(
            execution_class.description,
            "null pointer passed as argument 2, which is declared to never be null"
        );
        assert_eq!(execution_class.explanation, "");

        // Check crashline
        let crash_line = warning.crash_line();
        if let Ok(crash_line) = crash_line {
            assert_eq!(
                crash_line.to_string(),
                "/tarantool/src/box/sql/build.c:263:17"
            );
        } else {
            panic!("{}", crash_line.err().unwrap());
        }

        // Check warning
        let warning = &warnings[1];
        assert_eq!(warning.ubsan_report().len(), 17);

        // Check stacktrace
        let stacktrace = warning.extract_stacktrace();
        let Ok(stacktrace) = stacktrace else {
            panic!("{}", stacktrace.err().unwrap());
        };
        assert_eq!(stacktrace.len(), 14);

        // Check severity
        let execution_class = warning.severity();
        let Ok(execution_class) = execution_class else {
            panic!("{}", execution_class.err().unwrap());
        };
        assert_eq!(execution_class.severity, "NOT_EXPLOITABLE");
        assert_eq!(
            execution_class.short_description,
            "implicit-integer-sign-change"
        );
        assert_eq!(
            execution_class.description,
            "implicit conversion from type 'int' of value -8 (32-bit, signed) to type 'unsigned long' changed the value to 18446744073709551608 (64-bit, unsigned)"
        );
        assert_eq!(execution_class.explanation, "");

        // Check crashline
        let crash_line = warning.crash_line();
        if let Ok(crash_line) = crash_line {
            assert_eq!(
                crash_line.to_string(),
                "/tarantool/src/box/sql/vdbeaux.c:1417:6"
            );
        } else {
            panic!("{}", crash_line.err().unwrap());
        }

        // Check warning
        let warning = &warnings[2];
        assert_eq!(warning.ubsan_report().len(), 16);

        // Check stacktrace
        let stacktrace = warning.extract_stacktrace();
        let Ok(stacktrace) = stacktrace else {
            panic!("{}", stacktrace.err().unwrap());
        };
        assert_eq!(stacktrace.len(), 13);

        // Check severity
        let execution_class = warning.severity();
        let Ok(execution_class) = execution_class else {
            panic!("{}", execution_class.err().unwrap());
        };
        assert_eq!(execution_class.severity, "NOT_EXPLOITABLE");
        assert_eq!(
            execution_class.short_description,
            "nullptr-with-nonzero-offset"
        );
        assert_eq!(
            execution_class.description,
            "applying non-zero offset 1 to null pointer"
        );
        assert_eq!(execution_class.explanation, "");

        // Check crashline
        let crash_line = warning.crash_line();
        if let Ok(crash_line) = crash_line {
            assert_eq!(
                crash_line.to_string(),
                "/tarantool/src/lib/small/include/small/lf_lifo.h:86:59"
            );
        } else {
            panic!("{}", crash_line.err().unwrap());
        }
    }
}
