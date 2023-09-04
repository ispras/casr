#![no_main]

use libfuzzer_sys::fuzz_target;

use libcasr::asan::AsanStacktrace;
use libcasr::gdb::GdbStacktrace;
use libcasr::go::GoStacktrace;
use libcasr::java::JavaStacktrace;
use libcasr::python::PythonStacktrace;
use libcasr::stacktrace::ParseStacktrace;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let s = String::from_utf8_lossy(&data[1..]);
    match data[0] % 5 {
        0 => {
            // Asan
            if let Ok(st) = AsanStacktrace::extract_stacktrace(&s) {
                let _ = AsanStacktrace::parse_stacktrace(&st);
            }
        }
        1 => {
            // Go
            if let Ok(st) = GoStacktrace::extract_stacktrace(&s) {
                let _ = GoStacktrace::parse_stacktrace(&st);
            }
        }
        2 => {
            // Python
            if let Ok(st) = PythonStacktrace::extract_stacktrace(&s) {
                let _ = PythonStacktrace::parse_stacktrace(&st);
            }
        }
        3 => {
            // Java
            if let Ok(st) = JavaStacktrace::extract_stacktrace(&s) {
                let _ = JavaStacktrace::parse_stacktrace(&st);
            }
        }
        _ => {
            // Gdb
            if let Ok(st) = GdbStacktrace::extract_stacktrace(&s) {
                let _ = GdbStacktrace::parse_stacktrace(&st);
            }
        }
    }
});
