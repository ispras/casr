#![no_main]

use libfuzzer_sys::fuzz_target;

use libcasr::{
    asan::AsanStacktrace,
    csharp::CSharpStacktrace,
    gdb::GdbStacktrace,
    go::GoStacktrace,
    init_ignored_frames,
    java::JavaStacktrace,
    js::JsStacktrace,
    lua::LuaStacktrace,
    python::PythonStacktrace,
    stacktrace::{CrashLineExt, Filter, ParseStacktrace, Stacktrace},
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let s = String::from_utf8_lossy(&data[1..]);
    init_ignored_frames!("cpp", "csharp", "go", "java", "js", "python", "rust");
    match data[0] % 8 {
        0 => {
            // Asan
            if let Ok(raw) = AsanStacktrace::extract_stacktrace(&s) {
                if let Ok(st) = AsanStacktrace::parse_stacktrace(&raw) {
                    let _ = st.crash_line();
                }
            }
        }
        1 => {
            // C#
            if let Ok(raw) = CSharpStacktrace::extract_stacktrace(&s) {
                if let Ok(st) = CSharpStacktrace::parse_stacktrace(&raw) {
                    let _ = st.crash_line();
                }
            }
        }
        2 => {
            // Go
            if let Ok(raw) = GoStacktrace::extract_stacktrace(&s) {
                if let Ok(st) = GoStacktrace::parse_stacktrace(&raw) {
                    let _ = st.crash_line();
                }
            }
        }
        3 => {
            // Java
            if let Ok(raw) = JavaStacktrace::extract_stacktrace(&s) {
                if let Ok(st) = JavaStacktrace::parse_stacktrace(&raw) {
                    let _ = st.crash_line();
                }
            }
        }
        4 => {
            // JS
            if let Ok(raw) = JsStacktrace::extract_stacktrace(&s) {
                if let Ok(st) = JsStacktrace::parse_stacktrace(&raw) {
                    let _ = st.crash_line();
                }
            }
        }
        5 => {
            // Lua
            if let Ok(raw) = LuaStacktrace::extract_stacktrace(&s) {
                if let Ok(st) = LuaStacktrace::parse_stacktrace(&raw) {
                    let _ = st.crash_line();
                }
            }
        }
        6 => {
            // Python
            if let Ok(raw) = PythonStacktrace::extract_stacktrace(&s) {
                if let Ok(st) = PythonStacktrace::parse_stacktrace(&raw) {
                    let _ = st.crash_line();
                }
            }
        }
        _ => {
            // Gdb
            if let Ok(raw) = GdbStacktrace::extract_stacktrace(&s) {
                if let Ok(st) = GdbStacktrace::parse_stacktrace(&raw) {
                    let _ = st.crash_line();
                }
            }
        }
    }
});
