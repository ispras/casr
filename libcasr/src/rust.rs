//! Rust module implements `Exception` traits for Rust panic messages.
use crate::error::{Error, Result};
use crate::exception::Exception;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::ParseStacktrace;
use crate::stacktrace::StacktraceEntry;

use regex::Regex;

/// Structure provides an interface for parsing rust panic message.
pub struct RustPanic;

impl Exception for RustPanic {
    fn parse_exception(stderr: &str) -> Option<ExecutionClass> {
        let rexception = Regex::new(r"thread '.+?' panicked at (?:'(.*)'|.+?:\n(.*))").unwrap();
        let Some(captures) = rexception.captures(stderr) else {
            return None;
        };
        let message = if let Some(message) = captures.get(1) {
            message.as_str()
        } else {
            captures.get(2).unwrap().as_str()
        };
        Some(ExecutionClass::new((
            "NOT_EXPLOITABLE",
            "RustPanic",
            message,
            "",
        )))
    }
}

/// Structure provides an interface for processing stacktraces from RUST_BACKTRACE.
pub struct RustStacktrace;

impl ParseStacktrace for RustStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let re = Regex::new(r"( *\d+: *0x[0-9a-f]+ - .*\n(?: *at .*\n)?)").unwrap();
        let mut stacktrace: Vec<_> = re
            .find_iter(stream)
            .map(|s| s.as_str().trim().replace('\n', " "))
            .collect();

        if stacktrace.is_empty() {
            return Err(Error::Casr(
                "Couldn't find stacktrace entries in Rust panic output".to_string(),
            ));
        }

        // Filter out multiple spaces
        let re = Regex::new(r" +").unwrap();
        stacktrace = stacktrace
            .iter()
            .map(|e| re.replace_all(e, " ").to_string())
            .collect();

        Ok(stacktrace)
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let re = Regex::new(
            r#" *[0-9]+: +0x([0-9a-f]+) - (.+?)(?: *at (.+?):([0-9]+)(?::([0-9]+))?|$)"#,
        )
        .unwrap();
        let mut stentry = StacktraceEntry::default();

        let Some(caps) = re.captures(entry.as_ref()) else {
            return Err(Error::Casr(format!("Couldn't parse entry {}", entry)));
        };

        let num = caps.get(1).unwrap().as_str();
        let Ok(addr) = u64::from_str_radix(num, 16) else {
            return Err(Error::Casr(format!("Couldn't parse address: {num}")));
        };

        stentry.address = addr;
        stentry.function = caps.get(2).unwrap().as_str().to_string();

        if let Some(file_cap) = caps.get(3) {
            stentry.debug.file = file_cap.as_str().to_string();
        }

        if let Some(num) = caps.get(4) {
            let Ok(line) = num.as_str().parse::<u64>() else {
                return Err(Error::Casr(format!(
                    "Couldn't parse line: {}",
                    num.as_str()
                )));
            };
            stentry.debug.line = line;
        }

        if let Some(num) = caps.get(5) {
            let Ok(col) = num.as_str().parse::<u64>() else {
                return Err(Error::Casr(format!(
                    "Couldn't parse column: {}",
                    num.as_str()
                )));
            };
            stentry.debug.column = col;
        }
        Ok(stentry)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        constants::{
            STACK_FRAME_FILEPATH_IGNORE_REGEXES_CPP, STACK_FRAME_FILEPATH_IGNORE_REGEXES_GO,
            STACK_FRAME_FILEPATH_IGNORE_REGEXES_JAVA, STACK_FRAME_FILEPATH_IGNORE_REGEXES_PYTHON,
            STACK_FRAME_FILEPATH_IGNORE_REGEXES_RUST, STACK_FRAME_FUNCTION_IGNORE_REGEXES_CPP,
            STACK_FRAME_FUNCTION_IGNORE_REGEXES_GO, STACK_FRAME_FUNCTION_IGNORE_REGEXES_JAVA,
            STACK_FRAME_FUNCTION_IGNORE_REGEXES_PYTHON, STACK_FRAME_FUNCTION_IGNORE_REGEXES_RUST,
        },
        init_ignored_frames,
        stacktrace::{
            Filter, STACK_FRAME_FILEPATH_IGNORE_REGEXES, STACK_FRAME_FUNCTION_IGNORE_REGEXES,
        },
    };

    #[test]
    fn test_rust_parse_stacktrace() {
        let stream = r#"Running: ./artifacts/fuzz_target_1/crash-da39a3ee5e6b4b0d3255bfef95601890afd80709
thread '<unnamed>' panicked at fuzz_targets/fuzz_target_1.rs:6:9:
index out of bounds: the len is 0 but the index is 10
stack backtrace:
   0:     0x557e259f793c - std::backtrace_rs::backtrace::libunwind::trace::h7d5a50c97105e9c9
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/../../backtrace/src/backtrace/libunwind.rs:93:5
   1:     0x557e259f793c - std::backtrace_rs::backtrace::trace_unsynchronized::hf283bd0ba71b8b19
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/../../backtrace/src/backtrace/mod.rs:66:5
   2:     0x557e259f793c - std::sys_common::backtrace::_print_fmt::hbc3f1af55ab433e1
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:67:5
   3:     0x557e259f793c - <std::sys_common::backtrace::_print::DisplayBacktrace as core::fmt::Display>::fmt::h662df30e888949cd
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:44:22
   4:     0x557e25a5b2fc - core::fmt::rt::Argument::fmt::hf59806e96303ebc5
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/core/src/fmt/rt.rs:138:9
   5:     0x557e25a5b2fc - core::fmt::write::hf7279be296576ae3
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/core/src/fmt/mod.rs:1094:21
   6:     0x557e259ebbae - std::io::Write::write_fmt::h1ecf2bec14816818
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/io/mod.rs:1714:15
   7:     0x557e259f7724 - std::sys_common::backtrace::_print::hceca1ed09536a7dd
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:47:5
   8:     0x557e259f7724 - std::sys_common::backtrace::print::hb3d0e53175a9dc58
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:34:9
   9:     0x557e259fa81a - std::panicking::panic_hook_with_disk_dump::{{closure}}::hb5593ac8317ecfc8
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:280:22
  10:     0x557e259fa515 - std::panicking::panic_hook_with_disk_dump::hd03ff9ecbda8604b
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:314:9
  11:     0x557e2596a26a - <alloc::boxed::Box<F,A> as core::ops::function::Fn<Args>>::call::h18a21e1a94673da8
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/alloc/src/boxed.rs:2021:9
  12:     0x557e2596a26a - libfuzzer_sys::initialize::{{closure}}::h8376bf2914730228
                               at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/src/lib.rs:90:9
  13:     0x557e259fb073 - <alloc::boxed::Box<F,A> as core::ops::function::Fn<Args>>::call::h70ed5b57462ef04a
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/alloc/src/boxed.rs:2021:9
  14:     0x557e259fb073 - std::panicking::rust_panic_with_hook::h7bf02c396cdadbfd
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:757:13
  15:     0x557e259fade1 - std::panicking::begin_panic_handler::{{closure}}::hecf382f929251efa
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:631:13
  16:     0x557e259f7e66 - std::sys_common::backtrace::__rust_end_short_backtrace::hc87b776526608b83
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:170:18
  17:     0x557e259fab22 - rust_begin_unwind
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:619:5
  18:     0x557e258857b5 - core::panicking::panic_fmt::hab5931093cddd316
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/core/src/panicking.rs:72:14
  19:     0x557e25885969 - core::panicking::panic_bounds_check::he32d152932e65018
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/core/src/panicking.rs:180:5
  20:     0x557e259648d8 - fuzz_target_1::_::__libfuzzer_sys_run::h57dd03312252cd3c
                               at /tmp/rust_fuzzer/aa/fuzz/fuzz_targets/fuzz_target_1.rs:6:9
  21:     0x557e25963ef1 - rust_fuzzer_test_input
                               at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/src/lib.rs:224:17
  22:     0x557e25965059 - libfuzzer_sys::test_input_wrap::{{closure}}::h5f394bb52e995829
                               at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/src/lib.rs:61:9
  23:     0x557e25965059 - std::panicking::try::do_call::hf66b1fd52e40ef81
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:526:40
  24:     0x557e2596a498 - __rust_try
  25:     0x557e25969662 - std::panicking::try::hd9beb82fa7bd0c0d
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:490:19
  26:     0x557e25969662 - std::panic::catch_unwind::h7db6659f049817e5
                               at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panic.rs:142:14
  27:     0x557e25969662 - LLVMFuzzerTestOneInput
                               at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/src/lib.rs:59:22
  28:     0x557e25970b26 - _ZN6fuzzer6Fuzzer15ExecuteCallbackEPKhm
                               at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/libfuzzer/FuzzerLoop.cpp:612:15
  29:     0x557e25983c77 - _ZN6fuzzer10RunOneTestEPNS_6FuzzerEPKcm
                               at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/libfuzzer/FuzzerDriver.cpp:324:21
  30:     0x557e2598bb43 - _ZN6fuzzer12FuzzerDriverEPiPPPcPFiPKhmE
                               at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/libfuzzer/FuzzerDriver.cpp:860:19
  31:     0x557e258861b7 - main
                               at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/libfuzzer/FuzzerMain.cpp:20:30
  32:     0x7ffbc33c6d90 - __libc_start_call_main
                               at ./csu/../sysdeps/nptl/libc_start_call_main.h:58:16
  33:     0x7ffbc33c6e40 - __libc_start_main_impl
                               at ./csu/../csu/libc-start.c:392:3
  34:     0x557e25886205 - _start
  35:                0x0 - <unknown>
==220063== ERROR: libFuzzer: deadly signal
    #0 0x557e2592aae1  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0xdcae1) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #1 0x557e2599a79e  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x14c79e) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #2 0x557e259705d9  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x1225d9) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #3 0x7ffbc33df51f  (/lib/x86_64-linux-gnu/libc.so.6+0x4251f) (BuildId: 229b7dc509053fe4df5e29e8629911f0c3bc66dd)
    #4 0x7ffbc3433a7b  (/lib/x86_64-linux-gnu/libc.so.6+0x96a7b) (BuildId: 229b7dc509053fe4df5e29e8629911f0c3bc66dd)
    #5 0x7ffbc33df475  (/lib/x86_64-linux-gnu/libc.so.6+0x42475) (BuildId: 229b7dc509053fe4df5e29e8629911f0c3bc66dd)
    #6 0x7ffbc33c57f2  (/lib/x86_64-linux-gnu/libc.so.6+0x287f2) (BuildId: 229b7dc509053fe4df5e29e8629911f0c3bc66dd)
    #7 0x557e25a07026  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x1b9026) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #8 0x557e25882626  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x34626) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #9 0x557e2596a274  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x11c274) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #10 0x557e259fb072  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x1ad072) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #11 0x557e259fade0  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x1acde0) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #12 0x557e259f7e65  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x1a9e65) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #13 0x557e259fab21  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x1acb21) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #14 0x557e258857b4  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x377b4) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #15 0x557e25885968  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x37968) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #16 0x557e259648d7  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x1168d7) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #17 0x557e25963ef0  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x115ef0) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #18 0x557e25965058  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x117058) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #19 0x557e2596a497  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x11c497) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #20 0x557e25969661  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x11b661) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #21 0x557e25970b25  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x122b25) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #22 0x557e25983c76  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x135c76) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #23 0x557e2598bb42  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x13db42) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #24 0x557e258861b6  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x381b6) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)
    #25 0x7ffbc33c6d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 229b7dc509053fe4df5e29e8629911f0c3bc66dd)
    #26 0x7ffbc33c6e3f  (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f) (BuildId: 229b7dc509053fe4df5e29e8629911f0c3bc66dd)
    #27 0x557e25886204  (/tmp/rust_fuzzer/aa/fuzz/fuzz_target_1+0x38204) (BuildId: 96fbb986820f007790ddd8593e04cc4e46a76ac4)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal"#;
        let raw_stacktrace = &[
            "0: 0x557e259f793c - std::backtrace_rs::backtrace::libunwind::trace::h7d5a50c97105e9c9 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/../../backtrace/src/backtrace/libunwind.rs:93:5",
            "1: 0x557e259f793c - std::backtrace_rs::backtrace::trace_unsynchronized::hf283bd0ba71b8b19 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/../../backtrace/src/backtrace/mod.rs:66:5",
            "2: 0x557e259f793c - std::sys_common::backtrace::_print_fmt::hbc3f1af55ab433e1 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:67:5",
            "3: 0x557e259f793c - <std::sys_common::backtrace::_print::DisplayBacktrace as core::fmt::Display>::fmt::h662df30e888949cd at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:44:22",
            "4: 0x557e25a5b2fc - core::fmt::rt::Argument::fmt::hf59806e96303ebc5 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/core/src/fmt/rt.rs:138:9",
            "5: 0x557e25a5b2fc - core::fmt::write::hf7279be296576ae3 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/core/src/fmt/mod.rs:1094:21",
            "6: 0x557e259ebbae - std::io::Write::write_fmt::h1ecf2bec14816818 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/io/mod.rs:1714:15",
            "7: 0x557e259f7724 - std::sys_common::backtrace::_print::hceca1ed09536a7dd at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:47:5",
            "8: 0x557e259f7724 - std::sys_common::backtrace::print::hb3d0e53175a9dc58 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:34:9",
            "9: 0x557e259fa81a - std::panicking::panic_hook_with_disk_dump::{{closure}}::hb5593ac8317ecfc8 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:280:22",
            "10: 0x557e259fa515 - std::panicking::panic_hook_with_disk_dump::hd03ff9ecbda8604b at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:314:9",
            "11: 0x557e2596a26a - <alloc::boxed::Box<F,A> as core::ops::function::Fn<Args>>::call::h18a21e1a94673da8 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/alloc/src/boxed.rs:2021:9",
            "12: 0x557e2596a26a - libfuzzer_sys::initialize::{{closure}}::h8376bf2914730228 at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/src/lib.rs:90:9",
            "13: 0x557e259fb073 - <alloc::boxed::Box<F,A> as core::ops::function::Fn<Args>>::call::h70ed5b57462ef04a at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/alloc/src/boxed.rs:2021:9",
            "14: 0x557e259fb073 - std::panicking::rust_panic_with_hook::h7bf02c396cdadbfd at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:757:13",
            "15: 0x557e259fade1 - std::panicking::begin_panic_handler::{{closure}}::hecf382f929251efa at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:631:13",
            "16: 0x557e259f7e66 - std::sys_common::backtrace::__rust_end_short_backtrace::hc87b776526608b83 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/sys_common/backtrace.rs:170:18",
            "17: 0x557e259fab22 - rust_begin_unwind at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:619:5",
            "18: 0x557e258857b5 - core::panicking::panic_fmt::hab5931093cddd316 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/core/src/panicking.rs:72:14",
            "19: 0x557e25885969 - core::panicking::panic_bounds_check::he32d152932e65018 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/core/src/panicking.rs:180:5",
            "20: 0x557e259648d8 - fuzz_target_1::_::__libfuzzer_sys_run::h57dd03312252cd3c at /tmp/rust_fuzzer/aa/fuzz/fuzz_targets/fuzz_target_1.rs:6:9",
            "21: 0x557e25963ef1 - rust_fuzzer_test_input at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/src/lib.rs:224:17",
            "22: 0x557e25965059 - libfuzzer_sys::test_input_wrap::{{closure}}::h5f394bb52e995829 at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/src/lib.rs:61:9",
            "23: 0x557e25965059 - std::panicking::try::do_call::hf66b1fd52e40ef81 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:526:40",
            "24: 0x557e2596a498 - __rust_try",
            "25: 0x557e25969662 - std::panicking::try::hd9beb82fa7bd0c0d at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panicking.rs:490:19",
            "26: 0x557e25969662 - std::panic::catch_unwind::h7db6659f049817e5 at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/panic.rs:142:14",
            "27: 0x557e25969662 - LLVMFuzzerTestOneInput at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/src/lib.rs:59:22",
            "28: 0x557e25970b26 - _ZN6fuzzer6Fuzzer15ExecuteCallbackEPKhm at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/libfuzzer/FuzzerLoop.cpp:612:15",
            "29: 0x557e25983c77 - _ZN6fuzzer10RunOneTestEPNS_6FuzzerEPKcm at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/libfuzzer/FuzzerDriver.cpp:324:21",
            "30: 0x557e2598bb43 - _ZN6fuzzer12FuzzerDriverEPiPPPcPFiPKhmE at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/libfuzzer/FuzzerDriver.cpp:860:19",
            "31: 0x557e258861b7 - main at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/libfuzzer/FuzzerMain.cpp:20:30",
            "32: 0x7ffbc33c6d90 - __libc_start_call_main at ./csu/../sysdeps/nptl/libc_start_call_main.h:58:16",
            "33: 0x7ffbc33c6e40 - __libc_start_main_impl at ./csu/../csu/libc-start.c:392:3",
            "34: 0x557e25886205 - _start",
            "35: 0x0 - <unknown>"];

        let trace = raw_stacktrace
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();
        let bt = RustStacktrace::extract_stacktrace(stream).unwrap();

        assert_eq!(bt, trace);

        let mut stacktrace = RustStacktrace::parse_stacktrace(&bt).unwrap();
        init_ignored_frames!("rust");
        stacktrace.filter();

        assert_eq!(stacktrace[0].address, 0x557e259648d8);
        assert_eq!(
            stacktrace[0].function,
            "fuzz_target_1::_::__libfuzzer_sys_run::h57dd03312252cd3c".to_string()
        );
        assert_eq!(
            stacktrace[0].debug.file,
            "/tmp/rust_fuzzer/aa/fuzz/fuzz_targets/fuzz_target_1.rs".to_string()
        );
        assert_eq!(stacktrace[0].debug.line, 6);
        assert_eq!(stacktrace[0].debug.column, 9);
    }

    #[test]
    fn test_rust_panic() {
        let panic_info = r#"Running: ./artifacts/fuzz_target_1/crash-da39a3ee5e6b4b0d3255bfef95601890afd80709
thread '<unnamed>' panicked at fuzz_targets/fuzz_target_1.rs:6:9:
index out of bounds: the len is 0 but the index is 10
stack backtrace:"#;
        let Some(class) = RustPanic::parse_exception(panic_info) else {
            panic!("Couldn't get rust panic");
        };

        assert_eq!(
            class.description,
            "index out of bounds: the len is 0 but the index is 10"
        );
    }
}
