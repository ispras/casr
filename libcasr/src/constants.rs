//! Constants for signals and stack trace filtering.
/* Copyright 2020 Google LLC
Modifications copyright (C) 2023 ISP RAS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/// Regular expressions for java functions to be ignored.
pub const STACK_FRAME_FUNCTION_IGNORE_REGEXES_JAVA: &[&str] = &[
    r"^java\.base",
    r"^java\.lang",
    r"^java\.beans",
    r"^java\.time",
    r"^java\.math",
    r"^java\.rmi",
    r"^java\.net",
    r"^java\.security",
    r"^java\.text",
    r"^java\.awt",
    r"^java\.n?io",
    r"^javax\.",
];

/// Regular expressions for JS functions to be ignored.
pub const STACK_FRAME_FUNCTION_IGNORE_REGEXES_JS: &[&str] = &[
    // TODO
    r"^<anonymous>$",
];

/// Regular expressions for lua functions to be ignored.
pub const STACK_FRAME_FUNCTION_IGNORE_REGEXES_LUA: &[&str] = &[
    // TODO
    r"^[^.]$",
];

/// Regular expressions for python functions to be ignored.
pub const STACK_FRAME_FUNCTION_IGNORE_REGEXES_PYTHON: &[&str] = &[
    // TODO
    r"^[^.]$",
];

/// Regular expressions for rust functions to be ignored.
pub const STACK_FRAME_FUNCTION_IGNORE_REGEXES_RUST: &[&str] = &[
    r"^rust_begin_unwind",
    r"^rust_fuzzer_test_input",
    r"^rust_oom",
    r"^rust_panic",
    r"^std::io::Write::write_fmt",
    r"^std::panic",
    r"^std::process::abort",
    r"^__rust_start_panic",
    r"^core::fmt::write",
    r"^core::panicking",
    r"^core::result",
    r"^panic_abort::",
    r"^__rust_try",
];

/// Regular expressions for Go functions to be ignored.
pub const STACK_FRAME_FUNCTION_IGNORE_REGEXES_GO: &[&str] = &[
    // TODO
    r"^runtime\.",
];

/// Regular expressions for cpp functions to be ignored.
pub const STACK_FRAME_FUNCTION_IGNORE_REGEXES_CPP: &[&str] = &[
    // Function names (exact match).
    r"^abort$",
    r"^exit$",
    r"^pthread_create$",
    r"^pthread_kill$",
    r"^raise$",
    r"^tgkill$",
    r"^__chk_fail$",
    r"^__fortify_fail$",
    // Function names (startswith).
    r"^(|__)aeabi_",
    r"^(|__)memcmp",
    r"^(|__)memcpy",
    r"^(|__)memmove",
    r"^(|__)memset",
    r"^(|__)strcmp",
    r"^(|__)strcpy",
    r"^(|__)strdup",
    r"^(|__)strlen",
    r"^(|__)strncpy",
    r"^<null>",
    r"^Abort\(",
    r"^CFCrash",
    r"^ExitCallback",
    r"^IsSandboxedProcess",
    r"^MSanAtExitWrapper",
    r"^New",
    r"^RaiseException",
    r"^SbSystemBreakIntoDebugger",
    r"^SignalAction",
    r"^SignalHandler",
    r"^TestOneProtoInput",
    r"^WTF::",
    r"^WTFCrash",
    r"^X11Error",
    r"^_L_unlock_",
    r"^__GI_",
    r"^__asan::",
    r"^__asan_",
    r"^__assert_",
    r"^__cxa_atexit",
    r"^__cxa_rethrow",
    r"^__cxa_throw",
    r"^throw_exception",
    r"^__dump_stack",
    r"^__hwasan::",
    r"^__hwasan_",
    r"^__interceptor_",
    r"^__kasan_",
    r"^__libc_",
    r"^__lsan::",
    r"^__lsan_",
    r"^__msan::",
    r"^__msan_",
    r"^__pthread_kill",
    r"^__run_exit_handlers",
    r"^__rust_try",
    r"^__sanitizer::",
    r"^__sanitizer_",
    r"^__tsan::",
    r"^__tsan_",
    r"^__ubsan::",
    r"^__ubsan_",
    r"^_asan_",
    r"^_hwasan_",
    r"^_lsan_",
    r"^_msan_",
    r"^_objc_terminate",
    r"^_sanitizer_",
    r"^_start",
    r"^__libc_start_main",
    r"^_tsan_",
    r"^_ubsan_",
    r"^abort",
    r"^alloc::",
    r"^android\.app\.ActivityManagerProxy\.",
    r"^android\.os\.Parcel\.",
    r"^art::Thread::CreateNativeThread",
    r"^asan_",
    r"^asan\.module_ctor",
    r"^asan\.module_dtor",
    r"^calloc",
    r"^check_memory_region",
    r"^common_exit",
    r"^delete",
    r"^demangling_terminate_handler",
    r"^bt_terminate_handler",
    r"^dump_backtrace",
    r"^dump_stack",
    r"^exit_or_terminate_process",
    r"^fpehandler\(",
    r"^free",
    r"^g_log",
    r"^generic_cpp_",
    r"^gsignal",
    r"^kasan_",
    // LibFuzzer
    r"^fuzzer::",
    r"^libfuzzer_sys::initialize",
    //r"^main",
    r"^malloc",
    r"^mozalloc_",
    r"^new",
    r"^object_err",
    r"^operator",
    r"^print_trailer",
    r"^realloc",
    r"^report_failure",
    r"^scanf",
    r"^show_stack",
    r"^std::__terminate",
    r"^std::terminate",
    r"^std::sys::unix::abort",
    r"^std::sys_common::backtrace",
    r"^__scrt_common_main_seh",
    // Functions names (contains).
    r".*ASAN_OnSIGSEGV",
    r".*BaseThreadInitThunk",
    r".*DebugBreak",
    r".*DefaultDcheckHandler",
    r".*ForceCrashOnSigAbort",
    r".*MemoryProtection::CMemoryProtector",
    r".*PartitionAlloc",
    r".*RtlFreeHeap",
    r".*RtlInitializeExceptionChain",
    r".*RtlReportCriticalFailure",
    r".*RtlUserThreadStart",
    r".*RtlpHeapHandleError",
    r".*RtlpLogHeapFailure",
    r".*SkDebugf",
    r".*StackDumpSignalHandler",
    r".*__android_log_assert",
    r".*__tmainCRTStartup",
    r".*_asan_rtl_",
    r".*agent::asan::",
    r".*allocator_shim",
    r".*asan_Heap",
    r".*asan_check_access",
    r".*asan_osx_dynamic\.dylib",
    r".*assert",
    r".*base::FuzzedDataProvider",
    r".*base::allocator",
    r".*base::android::CheckException",
    r".*base::debug::BreakDebugger",
    r".*base::debug::CollectStackTrace",
    r".*base::debug::StackTrace::StackTrace",
    r".*ieee754\-",
    r".*libpthread",
    r".*logger",
    r".*logging::CheckError",
    r".*logging::ErrnoLogMessage",
    r".*logging::LogMessage",
    r".*stdext::exception::what",
    r".*v8::base::OS::Abort",
    // Pybindings
    r".*pybind",
    r"^PyCFunction",
    r"^PyObject",
    r"^PyEval",
    r"^PyRun",
    r"^Py_",
    r"^atheris::",
];

/// Regular expressions for с# functions to be ignored.
pub const STACK_FRAME_FUNCTION_IGNORE_REGEXES_CSHARP: &[&str] = &[
    // TODO
    r"^\(wrapper",
];

/// Regular expressions for paths to java files that should be ignored.
pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_JAVA: &[&str] = &[
    // TODO
    r"^[^.]$",
];

/// Regular expressions for paths to JS files that should be ignored.
pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_JS: &[&str] = &[
    // TODO
    // Anonymous functions
    r"^<anonymous>$",
    // Native locations (within V8’s libraries)
    r"^native$",
    // JS internal modules
    r"^(|node:)internal/?",
    r"^(|node:)events/?",
    // Jazzer.js internal modules
    r"node_modules/@jazzer.js",
    // jsfuzz internal modules
    r"node_modules/jsfuzz",
];

/// Regular expressions for paths to lua files that should be ignored.
pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_LUA: &[&str] = &[
    // TODO
    r"^[^.]$",
];

/// Regular expressions for paths to python files that should be ignored.
pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_PYTHON: &[&str] = &[
    // TODO
    r"^[^.]$",
];

/// Regular expressions for paths to rust files that should be ignored.
pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_RUST: &[&str] = &[
    r".*/rust(|c)/",
    // AFL
    r".*/afl-.*/.*\.rs",
    r".*/libfuzzer-sys-.*/.*\.rs",
];

/// Regular expressions for paths to Go files that should be ignored.
pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_GO: &[&str] = &[r".*go/src/runtime/"];

/// Regular expressions for paths to cpp files that should be ignored.
pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_CPP: &[&str] = &[
    // File paths.
    r".*/usr/include/c\+\+/",
    r".*\-gnu/c\+\+/",
    r".*\-gnu/bits/",
    r".*/clang/",
    r".*base/callback",
    r".*/AOSP\-toolchain/",
    r".*/bindings/ToV8\.h",
    r".*/crosstool/",
    r".*/gcc/",
    r".*sysdeps/",
    r".*/glibc\-",
    r".*/jemalloc/",
    r".*/libc\+\+",
    r".*/libc/",
    r".*/llvm\-build/",
    r".*/minkernel/crts/",
    r".*/sanitizer_common/",
    r".*/tcmalloc/",
    r".*/vc/include/",
    r".*/vctools/crt/",
    r".*/win_toolchain/",
    r".*libc\+\+/",
    r".*/cxxsupp/",
    r".*/util/generic/",
    // Sanitizers and LibFuzzer
    r".*/compiler\-rt/lib/",
    r".*/libfuzzer/lib/",
    r".*/clang.*\-rt/lib/",
    // Others (uncategorized).
    r".*\+Unknown",
    r".*<unknown module>",
    r".*Inline Function @",
    r"^<unknown>$",
    r"^\[vdso\]$",
    r"^linux-vdso.so.*$",
    r"^linux-gate.so.*$",
    r".*libc\.so",
    r".*libc\+\+\.so",
    r".*libc\+\+_shared\.so",
    r".*libstdc\+\+\.so",
    r".*libc-.*\.so",
    r".*libpthread\.so",
    r".*libasan\.so",
    r".*libubsan\.so",
    r".*asan_with_fuzzer\.so",
];

/// Regular expressions for paths to c# files that should be ignored.
pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_CSHARP: &[&str] = &[
    // TODO
    r"^[^.]$",
];

// Signal numbers
pub const SIGINFO_SIGILL: u32 = 4;
pub const SIGINFO_SIGTRAP: u32 = 5;
pub const SIGINFO_SIGABRT: u32 = 6;
pub const SIGINFO_SIGBUS: u32 = 7;
pub const SIGINFO_SIGFPE: u32 = 8;
pub const SIGINFO_SIGSEGV: u32 = 11;
pub const SIGINFO_SIGSYS: u32 = 31;

pub const SI_KERNEL: u32 = 0x80;
