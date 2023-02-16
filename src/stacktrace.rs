extern crate lazy_static;

use anyhow::{bail, Result};
use gdb_command::stacktrace::*;
use regex::Regex;
use std::fmt;
use std::sync::RwLock;

pub enum CrashLine {
    // source:line:column.
    Source(DebugInfo),
    // Binary module and offset.
    Module { file: String, offset: u64 },
}

impl fmt::Display for CrashLine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            CrashLine::Source(debug) => {
                if debug.line != 0 && debug.column != 0 {
                    write!(f, "{}:{}:{}", debug.file, debug.line, debug.column)
                } else if debug.line != 0 {
                    write!(f, "{}:{}", debug.file, debug.line)
                } else {
                    write!(f, "{}", debug.file)
                }
            }
            CrashLine::Module { file, offset } => {
                write!(f, "{file}+{offset:#x}")
            }
        }
    }
}

pub trait ProcessStacktrace {
    fn detect_stacktrace(_stream: &str) -> Result<Vec<String>> {
        bail!("Not implemented")
    }

    fn parse_stacktrace(_entries: &[String], _mappings: Option<&[String]>) -> Result<Stacktrace> {
        bail!("Not implemented")
    }

    /// Get crash line from stack trace: source:line or binary+offset.               
    ///                                                                              
    /// # Arguments   
    ///
    /// * 'trace' - Stacktrace type from gdb_command library
    ///
    /// # Return value
    ///
    /// Crash line as a 'CrashLine' enum.
    fn crash_line(trace: &Stacktrace) -> Result<CrashLine> {
        // Compile function regexp.
        let rstring = STACK_FRAME_FUNCTION_IGNORE_REGEXES
            .read()
            .unwrap()
            .iter()
            .map(|s| format!("({s})|"))
            .collect::<String>();
        let rfunction = Regex::new(&rstring[0..rstring.len() - 1]).unwrap();

        // Compile file regexp.
        let rstring = STACK_FRAME_FILEPATH_IGNORE_REGEXES
            .read()
            .unwrap()
            .iter()
            .map(|s| format!("({s})|"))
            .collect::<String>();
        let rfile = Regex::new(&rstring[0..rstring.len() - 1]).unwrap();

        let crash_entry = trace.iter().find(|entry| {
            (entry.function.is_empty() || !rfunction.is_match(&entry.function))
                && (entry.module.is_empty() || !rfile.is_match(&entry.module))
                && (entry.debug.file.is_empty() || !rfile.is_match(&entry.debug.file))
        });

        if let Some(crash_entry) = crash_entry {
            if !crash_entry.debug.file.is_empty() {
                return Ok(CrashLine::Source(crash_entry.debug.clone()));
            } else if !crash_entry.module.is_empty() && crash_entry.offset != 0 {
                return Ok(CrashLine::Module {
                    file: crash_entry.module.clone(),
                    offset: crash_entry.offset,
                });
            }

            bail!("Couldn't collect crash line from stack trace".to_string(),);
        }

        bail!("No stack trace entries after filtering".to_string(),);
    }
}

pub const STACK_FRAME_FUNCTION_IGNORE_REGEXES_PYTHON: &[&str] = &[
    // TODO
    r"^[^.]$",
];

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
];

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
    r"^scanf",
    r"^show_stack",
    r"^std::__terminate",
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
];

pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_PYTHON: &[&str] = &[
    // TODO
    r"^[^.]$",
];

pub const STACK_FRAME_FILEPATH_IGNORE_REGEXES_RUST: &[&str] = &[
    r".*/rust(|c)/",
    // AFL
    r".*/afl-.*/.*\.rs",
];

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
    // LibFuzzer
    r".*/compiler\-rt/lib/fuzzer/",
    // Others (uncategorized).
    r".*\+Unknown",
    r".*<unknown module>",
    r".*Inline Function @",
    r"^<unknown>$",
    r"^\[vdso\]$",
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

lazy_static::lazy_static! {
    // Regular expressions for functions to be ignored.
    pub static ref STACK_FRAME_FUNCTION_IGNORE_REGEXES: RwLock<Vec<String>> = RwLock::new(
        Vec::new());
    // Regular expressions for file paths to be ignored.
    pub static ref STACK_FRAME_FILEPATH_IGNORE_REGEXES: RwLock<Vec<String>> = RwLock::new(
        Vec::new());
}
