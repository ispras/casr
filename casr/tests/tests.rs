extern crate copy_dir;
extern crate regex;
extern crate serde_json;

use copy_dir::copy_dir;
use regex::Regex;
use serde_json::Value;
use std::env;
use std::fs;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

static EXE_CASR_CORE: &str = env!("CARGO_BIN_EXE_casr-core");
static EXE_CASR_AFL: &str = env!("CARGO_BIN_EXE_casr-afl");
static EXE_CASR_LIBFUZZER: &str = env!("CARGO_BIN_EXE_casr-libfuzzer");
static EXE_CASR_CLUSTER: &str = env!("CARGO_BIN_EXE_casr-cluster");
static EXE_CASR_SAN: &str = env!("CARGO_BIN_EXE_casr-san");
static EXE_CASR_UBSAN: &str = env!("CARGO_BIN_EXE_casr-ubsan");
static EXE_CASR_PYTHON: &str = env!("CARGO_BIN_EXE_casr-python");
static EXE_CASR_LUA: &str = env!("CARGO_BIN_EXE_casr-lua");
static EXE_CASR_JAVA: &str = env!("CARGO_BIN_EXE_casr-java");
static EXE_CASR_JS: &str = env!("CARGO_BIN_EXE_casr-js");
static EXE_CASR_CSHARP: &str = env!("CARGO_BIN_EXE_casr-csharp");
static EXE_CASR_GDB: &str = env!("CARGO_BIN_EXE_casr-gdb");
static PROJECT_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn abs_path(rpath: &str) -> String {
    // Define paths.
    let rpath = match std::env::consts::ARCH {
        "aarch64" => rpath.replace("bin", "arm_bin"),
        "riscv64" => rpath.replace("bin", "riscv_bin"),
        _ => {
            if std::env::consts::OS == "macos" {
                rpath.replace("bin", "mac_bin")
            } else {
                rpath.to_string()
            }
        }
    };
    let project_dir = PathBuf::from(PROJECT_DIR);
    let mut path = PathBuf::new();
    path.push(&project_dir);
    path.push(&rpath);

    path.as_os_str().to_str().unwrap().to_string()
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_segfault_on_pc() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_segFaultOnPc"),
        abs_path("tests/casr_tests/bin/test_segFaultOnPc"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "SegFaultOnPc");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_dest_av() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_destAv"),
        abs_path("tests/casr_tests/bin/test_destAv"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "DestAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_dest_av_near_null() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_destAvNearNull"),
        abs_path("tests/casr_tests/bin/test_destAvNearNull"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "DestAvNearNull");
    } else {
        panic!("Couldn't parse json report file.");
    }
}
#[test]
#[cfg(target_arch = "x86_64")]
fn test_return_av() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_returnAv"),
        abs_path("tests/casr_tests/bin/test_returnAv"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "ReturnAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_callAv"),
        abs_path("tests/casr_tests/bin/test_callAv"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "CallAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_call_av_tainted() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_callAvTainted"),
        abs_path("tests/casr_tests/bin/test_callAvTainted"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "CallAvTainted");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_source_av() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_sourceAv"),
        abs_path("tests/casr_tests/bin/test_sourceAv"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_source_av_near_null() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_sourceAvNearNull"),
        abs_path("tests/casr_tests/bin/test_sourceAvNearNull"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAvNearNull");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_abort() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_abort"),
        abs_path("tests/casr_tests/bin/test_abort"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "AbortSignal");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[ignore]
fn test_canary() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_canary"),
        abs_path("tests/casr_tests/bin/test_canary"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "StackGuard");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[ignore]
fn test_safe_func() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_safeFunc"),
        abs_path("tests/casr_tests/bin/test_safeFunc"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SafeFunctionCheck");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_bad_instruction() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_badInstruction"),
        abs_path("tests/casr_tests/bin/test_badInstruction"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "BadInstruction");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_stack_overflow() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_stackOverflow"),
        abs_path("tests/casr_tests/bin/test_stackOverflow"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "StackOverflow");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_dest_av_tainted() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_destAvTainted"),
        abs_path("tests/casr_tests/bin/test_destAvTainted"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "DestAvTainted");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_div_by_zero() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_DivByZero"),
        abs_path("tests/casr_tests/bin/test_DivByZero"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "FPE");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_segfault_on_pc32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_segFaultOnPc32"),
        abs_path("tests/casr_tests/bin/test_segFaultOnPc32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "SegFaultOnPc");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_destAv32"),
        abs_path("tests/casr_tests/bin/test_destAv32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "DestAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_near_null32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_destAvNearNull32"),
        abs_path("tests/casr_tests/bin/test_destAvNearNull32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "DestAvNearNull");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_return_av32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_returnAv32"),
        abs_path("tests/casr_tests/bin/test_returnAv32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "ReturnAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_callAv32"),
        abs_path("tests/casr_tests/bin/test_callAv32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "CallAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_sourceAv32"),
        abs_path("tests/casr_tests/bin/test_sourceAv32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_near_null32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_sourceAvNearNull32"),
        abs_path("tests/casr_tests/bin/test_sourceAvNearNull32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAvNearNull");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_abort32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_abort32"),
        abs_path("tests/casr_tests/bin/test_abort32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "AbortSignal");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[ignore]
#[cfg(target_arch = "x86_64")]
fn test_canary32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_canary32"),
        abs_path("tests/casr_tests/bin/test_canary32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "StackGuard");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[ignore]
#[cfg(target_arch = "x86_64")]
fn test_safe_func32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_safeFunc32"),
        abs_path("tests/casr_tests/bin/test_safeFunc32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SafeFunctionCheck");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_bad_instruction32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_badInstruction32"),
        abs_path("tests/casr_tests/bin/test_badInstruction32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "BadInstruction");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_div_by_zero32() {
    let paths = [
        abs_path("tests/casr_tests/bin/core.test_DivByZero32"),
        abs_path("tests/casr_tests/bin/test_DivByZero32"),
    ];
    // Run casr.
    let output = Command::new(EXE_CASR_CORE)
        .args(["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "FPE");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_abort_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_abort"),
            "A",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "AbortSignal");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_sigbus() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_sigbus"),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "DestAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_sigtrap() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_sig_me"),
            "5",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "TrapSignal");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_segfault_on_pc_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_segFaultOnPc"),
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "SegFaultOnPc");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_destAv"),
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "DestAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_near_null_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_destAvNearNull"),
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "DestAvNearNull");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_return_av_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_returnAv"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let disasm = report["Disassembly"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_returnAv.c:33")
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_returnAv+0x"),
            // We can't hardcode the offset because we rebuild tests every time.
        );

        // Disassembly test
        assert!(disasm[0].contains("ret"), "Bad disassembly");
        assert!(
            disasm[1].contains("nop") && disasm[1].contains("[rax+rax*1+0x0]"),
            "Bad disassembly"
        );
        assert!(disasm[2].contains("nop"), "Bad disassembly");
        assert!(disasm[3].contains("push   r15"), "Bad disassembly");
        assert!(disasm[4].contains("push   r14"), "Bad disassembly");
        assert!(disasm[5].contains("mov    r15,rdx"), "Bad disassembly");
        assert!(disasm[6].contains("push   r13"), "Bad disassembly");
        assert!(disasm[7].contains("push   r12"), "Bad disassembly");
        assert!(
            disasm[8].contains("lea    r12,[rip+0x200656]"),
            "Bad disassembly"
        );
        assert!(disasm[9].contains("push   rbp"), "Bad disassembly");
        assert!(
            disasm[10].contains("lea    rbp,[rip+0x200656]"),
            "Bad disassembly"
        );
        assert!(disasm[11].contains("push   rbx"), "Bad disassembly");
        assert!(disasm[12].contains("mov    r13d,edi"), "Bad disassembly");
        assert!(disasm[13].contains("mov    r14,rsi"), "Bad disassembly");
        assert!(disasm[14].contains("sub    rbp,r12"), "Bad disassembly");
        assert!(disasm[15].contains("sub    rsp,0x8"), "Bad disassembly");

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "ReturnAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_callAv"),
            "-11111111",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "CallAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av_tainted_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_callAvTainted"),
            "-11111111",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "CallAvTainted");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_sourceAv"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_near_null_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_sourceAvNearNull"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAvNearNull");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_canary_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_canary"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "StackGuard");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_safe_func_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_safeFunc"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SafeFunctionCheck");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_bad_instruction_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_badInstruction"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "BadInstruction");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_stack_overflow_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_stackOverflow"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "StackOverflow");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_tainted_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_destAvTainted"),
            "-111111111",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "DestAvTainted");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_div_by_zero_gdb() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_DivByZero"),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "FPE");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_div_by_zero_stdin_gdb() {
    // Test casr-san stdin
    let paths = [
        abs_path("tests/casr_tests/test_asan_stdin.cpp"),
        abs_path("tests/tmp_tests_casr/test_stdin"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!("clang++ -O0 -g {} -o {}", &paths[0], &paths[1]))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let mut tempfile = fs::File::create("/tmp/casr_gdb_div_by_zero").unwrap();
    tempfile.write_all(b"1").unwrap();
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--stdin",
            "/tmp/casr_gdb_div_by_zero",
            "--",
            &paths[1],
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_file("/tmp/casr_gdb_div_by_zero").unwrap();

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let stdin = report["Stdin"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert!(stdin.contains("/tmp/casr_gdb_div_by_zero"));
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "FPE");
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_file(&paths[1]);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_abort_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_abort32"),
            "A",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "AbortSignal");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_segfault_on_pc_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_segFaultOnPc32"),
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "SegFaultOnPc");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_destAv32"),
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "DestAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_near_null_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_destAvNearNull32"),
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "DestAvNearNull");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_return_av_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_returnAv32"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "ReturnAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_callAv32"),
            "-11111111",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "CallAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_sourceAv32"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAv");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_near_null_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_sourceAvNearNull32"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAvNearNull");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_canary_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_canary32"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "StackGuard");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_safe_func_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_safeFunc32"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SafeFunctionCheck");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_bad_instruction_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_badInstruction32"),
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "BadInstruction");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_div_by_zero_gdb32() {
    // Run casr-gdb.
    let output = Command::new(EXE_CASR_GDB)
        .args([
            "--stdout",
            "--",
            &abs_path("tests/casr_tests/bin/test_DivByZero32"),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Test report.
    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "FPE");
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
fn test_casr_cluster_s() {
    let paths = [
        abs_path("tests/casr_tests/casrep/similarity_test/3.casrep"),
        abs_path("tests/casr_tests/casrep/similarity_test/4.casrep"),
    ];
    let mut output = Command::new(EXE_CASR_CLUSTER)
        .args(["-s", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res: f64 = output
        .stdout
        .drain(0..7)
        .map(|x| x as char)
        .collect::<String>()
        .parse::<f64>()
        .unwrap();
    if res > 0.45 {
        panic!(
            "Too high similarity, mistake. Stdout:{:?}\nDigit: {}\n",
            output.stdout.as_slice(),
            res
        );
    }

    let paths = [
        abs_path("tests/casr_tests/casrep/similarity_test/1.casrep"),
        abs_path("tests/casr_tests/casrep/similarity_test/2.casrep"),
    ];
    let mut output = Command::new(EXE_CASR_CLUSTER)
        .args(["-s", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res: f64 = output
        .stdout
        .drain(0..7)
        .map(|x| x as char)
        .collect::<String>()
        .parse::<f64>()
        .unwrap();
    if res < 0.80 {
        panic!(
            "Too small similarity, mistake. Stdout:{:?}\nDigit: {}\n",
            output.stdout.as_slice(),
            res
        );
    }

    let paths = [
        abs_path("tests/casr_tests/casrep/similarity_test/5.casrep"),
        abs_path("tests/casr_tests/casrep/similarity_test/6.casrep"),
    ];
    let mut output = Command::new(EXE_CASR_CLUSTER)
        .args(["-s", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res: f64 = output
        .stdout
        .drain(0..7)
        .map(|x| x as char)
        .collect::<String>()
        .parse::<f64>()
        .unwrap();
    if res < 0.99 {
        panic!(
            "Too small similarity, mistake. Stdout:{:?}\nDigit: {}\n",
            output.stdout.as_slice(),
            res
        );
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_gdb_exception() {
    let paths = [
        abs_path("tests/casr_tests/test_exception.cpp"),
        abs_path("tests/tmp_tests_casr/test_exception"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!("clang++ -O0 -g {} -o {}", &paths[0], &paths[1]))
        .status()
        .expect("failed to execute clang");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_GDB)
        .args(["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_short_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let severity_desc = report["CrashSeverity"]["Description"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "ExceptionMessage");
        assert!(severity_short_desc.contains("std::runtime_error"));
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_file(&paths[1]);
}

#[test]
fn test_casr_cluster_c() {
    let paths = [
        abs_path("tests/casr_tests/casrep/test_clustering_small"),
        abs_path("tests/tmp_tests_casr/clustering_out"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-c", &paths[0], &paths[1]])
        .env("CASR_CLUSTER_UNIQUE_CRASHLINE", "1")
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res = String::from_utf8_lossy(&output.stdout);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 9, "Clusters count mismatch.");

    // Check crashline deduplication
    let re =
        Regex::new(r"Number of reports before crashline deduplication: (?P<before>\d+)").unwrap();
    let before_cnt = re
        .captures(&res)
        .unwrap()
        .name("before")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(before_cnt, 12, "Before count mismatch.");

    let re =
        Regex::new(r"Number of reports after crashline deduplication: (?P<after>\d+)").unwrap();
    let after_cnt = re
        .captures(&res)
        .unwrap()
        .name("after")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(after_cnt, 11, "After count mismatch.");

    // 2.casrep and 20.caserp without crashlines => no dedup
    // 3.casrep and 30.caserp with crashlines => dedup
    // Thus, cluster (cl7) with 2.casrep has 2 casreps and cl9 too
    // But others have 1 casrep
    for i in 1..clusters_cnt + 1 {
        let cluster_path = paths[1].to_owned() + "/cl" + &i.to_string();
        let size = std::fs::read_dir(cluster_path.clone()).unwrap().count();
        let num = if i == 7 || i == 9 { 2 } else { 1 };
        assert_eq!(size, num);
    }

    let _ = std::fs::remove_dir_all(&paths[1]);
}

#[test]
fn test_casr_cluster_c_huge_san() {
    let paths = [
        abs_path("tests/casr_tests/casrep/test_clustering_san"),
        abs_path("tests/tmp_tests_casr/clustering_huge_out_san"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-d", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-j", "6", "-c", &paths[1], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res = String::from_utf8_lossy(&output.stdout);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 12, "Invalid number of clusters");

    let mut cluster_sizes = vec![];

    for i in 1..clusters_cnt + 1 {
        let size = std::fs::read_dir(paths[1].to_owned() + "/cl" + &i.to_string())
            .unwrap()
            .count();
        cluster_sizes.push(size);
    }

    cluster_sizes.sort();

    for (i, x) in cluster_sizes.iter().enumerate() {
        let size = if i < 8 { 1 } else { 2 };
        assert_eq!(*x, size);
    }

    let _ = std::fs::remove_dir_all(&paths[1]);
}

#[test]
fn test_casr_cluster_c_huge_gdb() {
    let paths = [
        abs_path("tests/casr_tests/casrep/test_clustering_gdb"),
        abs_path("tests/tmp_tests_casr/clustering_huge_out_gdb"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-d", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-j", "6", "-c", &paths[1], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res = String::from_utf8_lossy(&output.stdout);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 12, "Invalid number of clusters");

    let mut cluster_sizes = vec![];

    for i in 1..clusters_cnt + 1 {
        let size = std::fs::read_dir(paths[1].to_owned() + "/cl" + &i.to_string())
            .unwrap()
            .count();
        cluster_sizes.push(size);
    }

    cluster_sizes.sort();

    for (i, x) in cluster_sizes.iter().enumerate() {
        let size: usize;
        if i < 7 {
            size = 1;
        } else if i < 11 {
            size = 2;
        } else {
            size = 3;
        }
        assert_eq!(*x, size);
    }

    let _ = std::fs::remove_dir_all(&paths[1]);
}

#[test]
fn test_casr_cluster_d_and_m() {
    let paths = [
        abs_path("tests/casr_tests/casrep/dedup/in"),
        abs_path("tests/tmp_tests_casr/dedup_out"),
        abs_path("tests/tmp_tests_casr/dedup_diff"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);
    let _ = fs::remove_dir_all(&paths[2]);

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-d", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let mut dirvec = match fs::read_dir(&paths[1]) {
        Ok(vec) => vec,
        Err(why) => {
            panic!("{:?}", why.kind());
        }
    };

    // For further purposes
    let casrep = dirvec.next().unwrap().unwrap().path();
    let counter = dirvec.count();
    if counter != 1 {
        panic!("Bad deduplication, casreps {}", counter + 1);
    }

    // Removing one report from target dir for merge testing
    let _ = std::fs::remove_file(casrep);

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-m", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    let out = String::from_utf8_lossy(&output.stdout);

    assert!(
        out.contains("Merged 1 new reports") && (fs::read_dir(&paths[1]).unwrap().count() == 2),
        "Something went wrong while merging directories"
    );

    // Test --diff option
    dirvec = match fs::read_dir(&paths[1]) {
        Ok(vec) => vec,
        Err(why) => {
            panic!("{:?}", why.kind());
        }
    };
    let casrep = dirvec.next().unwrap().unwrap().path();
    let _ = std::fs::remove_file(casrep);
    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["--diff", &paths[0], &paths[1], &paths[2]])
        .output()
        .expect("failed to start casr-cluster");
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(
        out.contains("Diff of 1 new reports") && (fs::read_dir(&paths[2]).unwrap().count() == 1),
        "Something went wrong while diffing directories"
    );
}

#[test]
fn test_casr_cluster_u() {
    let paths = [
        abs_path("tests/casr_tests/casrep/test_clustering_small"),
        abs_path("tests/tmp_tests_casr/updating_out"),
        abs_path("tests/tmp_tests_casr/updating_out/cl7/20.casrep"),
        abs_path("tests/tmp_tests_casr/updating_out/cl8"),
        abs_path("tests/tmp_tests_casr/updating_out/cl9"),
        abs_path("tests/tmp_tests_casr/updating_out/cl9/40.casrep"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-c", &paths[0], &paths[1]])
        .env("CASR_CLUSTER_UNIQUE_CRASHLINE", "1")
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res = String::from_utf8_lossy(&output.stdout);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 9, "Clusters count mismatch.");

    let _ = std::fs::remove_file(&paths[2]);
    let _ = std::fs::remove_file(&paths[5]);
    let _ = std::fs::remove_dir_all(&paths[3]);
    let _ = std::fs::rename(&paths[4], &paths[3]);

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-u", &paths[0], &paths[1]])
        .env("CASR_CLUSTER_UNIQUE_CRASHLINE", "1")
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res = String::from_utf8_lossy(&output.stdout);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of casreps added to old clusters: (?P<added>\d+)").unwrap();
    let added_cnt = re
        .captures(&res)
        .unwrap()
        .name("added")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(added_cnt, 1, "Added count mismatch.");

    let re = Regex::new(r"Number of duplicates: (?P<duplicates>\d+)").unwrap();
    let duplicates_cnt = re
        .captures(&res)
        .unwrap()
        .name("duplicates")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(duplicates_cnt, 9, "Duplicates count mismatch.");

    let re = Regex::new(r"Number of new clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 1, "Clusters count mismatch.");

    let re = Regex::new(
        r"Number of reports after crashline deduplication in new clusters: (?P<after>\d+)",
    )
    .unwrap();
    let after_cnt = re
        .captures(&res)
        .unwrap()
        .name("after")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(after_cnt, 1, "After count mismatch.");

    let re = Regex::new(r"Cluster silhouette score: (?P<sil>\d+.\d+)").unwrap();
    let sil = re
        .captures(&res)
        .unwrap()
        .name("sil")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<f64>()
        .unwrap();

    assert_eq!(sil, 0.15436556855344655, "Silhouette score mismatch.");

    // Test estimation
    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-e", &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res = String::from_utf8_lossy(&output.stdout);

    assert!(!res.is_empty());

    let re = Regex::new(r"Cluster silhouette score: (?P<sil>\d+.\d+)").unwrap();
    let sil = re
        .captures(&res)
        .unwrap()
        .name("sil")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<f64>()
        .unwrap();

    assert_eq!(sil, 0.15436556855344655, "Silhouette score mismatch.");

    let _ = std::fs::remove_dir_all(&paths[1]);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_san() {
    // Double free test
    let paths = [
        abs_path("tests/casr_tests/test_asan_df.cpp"),
        abs_path("tests/tmp_tests_casr/test_asan_df"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address -O0 -g {} -o {}",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1]])
        .env("CASR_STRIP_PATH", env::current_dir().unwrap())
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout: {}\n. Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let stacktrace = report["Stacktrace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        assert!(stacktrace.len() > 3);
        assert!(stacktrace[0].contains("free"));
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "double-free");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .eq("tests/casr_tests/test_asan_df.cpp:8:5")
                // We build a test on ubuntu18 and run it on ubuntu20.
                // Debug information is broken.
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_asan_df+0x") // We can't hardcode the offset because we rebuild tests every time.
        );
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_file(&paths[1]);
    // Stack-buffer-overflow test
    let paths = [
        abs_path("tests/casr_tests/test_asan_sbo.cpp"),
        abs_path("tests/tmp_tests_casr/test_asan_sbo"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address -O0 -g {} -o {}",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let asan_report = report["AsanReport"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let sources = report["Source"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let stacktrace = report["Stacktrace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        assert!(stacktrace.len() > 2);
        assert!(stacktrace[0].contains("main"));

        // Sources test
        assert!(sources[0].contains("    5      {"), "Bad sources");
        assert!(
            sources[1].contains("    6          int a[3];"),
            "Bad sources"
        );
        assert!(
            sources[2].contains("    7          for (int i = 0; i < 4; ++i)"),
            "Bad sources"
        );
        assert!(sources[3].contains("    8          {"), "Bad sources");
        assert!(
            sources[4].contains("--->9              a[i] = 1;"),
            "Bad sources"
        );
        assert!(sources[5].contains("    10         }"), "Bad sources");
        assert!(
            sources[6].contains("    11         return a[2];"),
            "Bad sources"
        );
        assert!(sources[7].contains("    12     }"), "Bad sources");

        assert!(!asan_report.is_empty() && asan_report[1].contains("WRITE"));

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "stack-buffer-overflow(write)");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_asan_sbo.cpp:9:14")
                // We build a test on ubuntu18 and run it on ubuntu20.
                // Debug information is broken.
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_asan_sbo+0x") // We can't hardcode the offset because we rebuild tests every time.
        );
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_file(&paths[1]);
    // Memory leaks test
    let paths = [
        abs_path("tests/casr_tests/test_asan_leak.cpp"),
        abs_path("tests/tmp_tests_casr/test_asan_leak"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address -O0 -g {} -o {}",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(
            3 + 2
                * (std::env::consts::ARCH == "aarch64"
                    || lsb_release::info().unwrap().version == "24.04") as usize,
            report["Stacktrace"].as_array().unwrap().iter().count()
        );
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "memory-leaks");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("leak.cpp:8:9")
                // We build a test on ubuntu18 and run it on ubuntu20.
                // Debug information is broken.
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_asan_leak+0x") // We can't hardcode the offset because we rebuild tests every time.
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
    // Test casr-san stdin
    let paths = [
        abs_path("tests/casr_tests/test_asan_stdin.cpp"),
        abs_path("tests/tmp_tests_casr/test_asan_stdin"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address -O0 -g {} -o {}",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let mut tempfile = fs::File::create("/tmp/CasrSanTemp").unwrap();
    tempfile.write_all(b"2").unwrap();
    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--stdin", "/tmp/CasrSanTemp", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_file("/tmp/CasrSanTemp").unwrap();

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let stdin = report["Stdin"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let stacktrace = report["Stacktrace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        assert!(stacktrace.len() > 2);
        assert!(stacktrace[0].contains("main"));

        assert!(stdin.contains("/tmp/CasrSanTemp"));
        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "heap-buffer-overflow(write)");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("stdin.cpp:20:14")
                // We build a test on ubuntu18 and run it on ubuntu20.
                // Debug information is broken.
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_asan_stdin+0x") // We can't hardcode the offset because we rebuild tests every time.
        );
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_file(&paths[1]);
    // Test casr-san ASLR
    let paths = [
        abs_path("tests/casr_tests/test_asan_sbo.cpp"),
        abs_path("tests/tmp_tests_casr/test_asan_sbo"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address -O0 -g {} -o {}",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let output1 = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");
    let output2 = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output1.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output2.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let re = Regex::new(
        r"==[0-9]+==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x([0-9a-f]+)",
    )
    .unwrap();
    let _ = std::fs::remove_file(&paths[1]);

    let report1: Result<Value, _> = serde_json::from_slice(&output1.stdout);
    let report2: Result<Value, _> = serde_json::from_slice(&output2.stdout);
    if let Ok(rep1) = report1
        && let Ok(rep2) = report2
    {
        let asan1 = rep1["AsanReport"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .next()
            .unwrap();
        let first_addr = re
            .captures(&asan1)
            .unwrap()
            .get(1)
            .unwrap()
            .as_str()
            .to_string();
        let asan2 = rep2["AsanReport"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .next()
            .unwrap();
        let second_addr = re
            .captures(&asan2)
            .unwrap()
            .get(1)
            .unwrap()
            .as_str()
            .to_string();
        assert_eq!(
            first_addr, second_addr,
            "Addresses must be equal! {first_addr} != {second_addr}"
        );
        return;
    }

    panic!("Couldn't parse json report file.");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_san_msan() {
    let paths = [
        abs_path("tests/casr_tests/test_msan.cpp"),
        abs_path("tests/tmp_tests_casr/test_msan"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=memory -O0 {} -o {}",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout: {}\n. Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let stacktrace = report["Stacktrace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        assert!(stacktrace.len() > 2);
        assert!(stacktrace[0].contains("in main"));
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "use-of-uninitialized-value");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .eq("tests/casr_tests/test_msan.cpp:12:9")
                // We build a test on ubuntu18 and run it on ubuntu20.
                // Debug information is broken.
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_msan+0x") // We can't hardcode the offset because we rebuild tests every time.
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
    let _ = std::fs::remove_file(&paths[1]);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_san_segf_near_null() {
    let paths = [
        abs_path("tests/casr_tests/test_asan_segf.cpp"),
        abs_path("tests/tmp_tests_casr/test_asan_segfnearnull"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address -O0 -g {} -o {}",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let stacktrace = report["Stacktrace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        assert!(stacktrace.len() > 2);
        assert!(stacktrace[0].contains("main"));

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAvNearNull");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_asan_segf.cpp:12")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1], "1"])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let stacktrace = report["Stacktrace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        assert!(stacktrace.len() > 2);
        assert!(stacktrace[0].contains("main"));
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_asan_segf.cpp:14")
        );

        assert_eq!(severity_type, "PROBABLY_EXPLOITABLE");
        assert_eq!(severity_desc, "DestAvNearNull");
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_file(&paths[1]);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_san_segf() {
    let paths = [
        abs_path("tests/casr_tests/test_asan_segf.cpp"),
        abs_path("tests/tmp_tests_casr/test_asan_segf"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address -O0 -g {} -o {}",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1], "1", "1"])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let stacktrace = report["Stacktrace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        assert!(stacktrace.len() > 2);
        assert!(stacktrace[0].contains("main"));
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_asan_segf.cpp:16")
        );

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "SourceAv");
    } else {
        panic!("Couldn't parse json report file.");
    }

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1], "1", "1", "1"])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let stacktrace = report["Stacktrace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        assert!(stacktrace.len() > 2);
        assert!(stacktrace[0].contains("main"));
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_asan_segf.cpp:18")
        );

        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "DestAv");
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_file(&paths[1]);
}

#[test]
#[cfg(not(target_os = "macos"))]
fn test_casr_san_exception() {
    let paths = [
        abs_path("tests/casr_tests/test_exception.cpp"),
        abs_path("tests/tmp_tests_casr/test_asan_exception"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!("g++ -O0 -g {} -o {}", &paths[0], &paths[1]))
        .status()
        .expect("failed to execute clang");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_short_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let severity_desc = report["CrashSeverity"]["Description"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "ExceptionMessage");
        assert!(severity_short_desc.contains("std::runtime_error"));
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_file(&paths[1]);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_san_rust_panic() {
    let paths = [
        abs_path("tests/casr_tests/test_rust_panic/fuzz"),
        abs_path("tests/tmp_tests_casr/test_rust_panic_fuzz"),
        abs_path(
            "tests/tmp_tests_casr/test_rust_panic_fuzz/x86_64-unknown-linux\
            -gnu/release/fuzz_target",
        ),
    ];

    let rustup_output = Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .expect("failed to execute rustup");
    let rustup_stdout = String::from_utf8_lossy(&rustup_output.stdout).to_string();
    let re = Regex::new(r"(?P<toolchain>nightly-\d{4}-\d{2}-\d{2})").unwrap();
    let toolchain = if let Some(tc) = re.captures(rustup_stdout.as_str()) {
        tc.name("toolchain").map(|x| x.as_str()).unwrap()
    } else {
        "nightly"
    };

    let cargo = Command::new("cargo")
        .args([
            ("+".to_owned() + toolchain).as_str(),
            "fuzz",
            "build",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--fuzz-dir",
            &paths[0],
            "--target-dir",
            &paths[1],
            "-s",
            "address",
        ])
        // Clear env
        .env("RUSTFLAGS", "")
        .env("RUSTDOCFLAGS", "")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to execute cargo fuzz build");

    assert!(cargo.success());

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[2], &paths[2]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_short_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();
        let severity_desc = report["CrashSeverity"]["Description"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_short_desc, "RustPanic");
        assert_eq!(severity_desc, "PanicMessage");
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_dir_all(&paths[1]);
}

#[test]
#[ignore]
#[cfg(target_arch = "x86_64")]
fn test_casr_san_sigbus() {
    let paths = [
        abs_path("tests/casr_tests/test_sigbus.c"),
        abs_path("tests/tmp_tests_casr/test_asan_sigbus"),
    ];

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang -fsanitize=address -O0 -g {} -o {}",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(1, report["Stacktrace"].as_array().unwrap().iter().count());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "AccessViolation");
    } else {
        panic!("Couldn't parse json report file.");
    }

    let _ = std::fs::remove_file(&paths[1]);
}

#[test]
fn test_casr_ignore_frames() {
    let paths = [
        abs_path("tests/casr_tests/test_casr_ignore_frames/psan.sh"),
        abs_path("tests/casr_tests/test_casr_ignore_frames/ign1.lst"),
        abs_path("tests/casr_tests/test_casr_ignore_frames/ign2.lst"),
    ];

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--ignore", &paths[1], "--", &paths[0]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("size-too-big.cpp:13:25")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--ignore", &paths[2], "--", &paths[0]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("size-too-big.cpp:16:5")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }

    let output = Command::new(EXE_CASR_SAN)
        .args(["--stdout", "--", &paths[0]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("size-too-big.cpp:12:25")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_afl() {
    use std::collections::HashMap;

    let paths = [
        abs_path("tests/casr_tests/casrep/afl-out-xlnt"),
        abs_path("tests/tmp_tests_casr/casr_afl_out"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);
    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));
    let _ = fs::copy(abs_path("tests/casr_tests/bin/load_afl"), "/tmp/load_afl");
    let _ = fs::copy(abs_path("tests/casr_tests/bin/load_sydr"), "/tmp/load_sydr");

    let bins = Path::new(EXE_CASR_AFL).parent().unwrap();
    let output = Command::new(EXE_CASR_AFL)
        .args([
            "-i",
            &paths[0],
            "-o",
            &paths[1],
            "--",
            "/tmp/load_sydr",
            "@@",
        ])
        .env(
            "PATH",
            format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .expect("failed to start casr-afl");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let res = String::from_utf8_lossy(&output.stderr);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&res)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 33, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 20, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                    if e.extension().is_some() && e.extension().unwrap() == "gdb" {
                        e = e.with_extension("");
                    }
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));
    assert_eq!(storage.values().filter(|x| **x == 3).count(), 13); // casr-gdb
    let _ = fs::remove_file("/tmp/load_sydr");
    let _ = fs::remove_file("/tmp/load_afl");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_afl_ignore_cmd() {
    use std::collections::HashMap;

    let paths = [
        abs_path("tests/casr_tests/casrep/afl-out-xlnt-small"),
        abs_path("tests/tmp_tests_casr/casr_afl_ignore_cmd_out"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);
    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));
    let load_afl = abs_path("tests/casr_tests/bin/load_afl");

    let output = Command::new(EXE_CASR_AFL)
        .args([
            "--ignore-cmdline",
            "-i",
            &paths[0],
            "-o",
            &paths[1],
            "--",
            &load_afl,
        ])
        .output()
        .expect("failed to start casr-afl");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let res = String::from_utf8_lossy(&output.stderr);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&res)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 6, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 5, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x == 2));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_ubsan() {
    // Copy files to tmp dir
    let work_dir = abs_path("tests/casr_tests/ubsan");
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_ubsan");

    let _ = fs::remove_dir_all(&test_dir);
    let _ = copy_dir(work_dir, &test_dir).unwrap();

    let paths = [
        abs_path("tests/tmp_tests_casr/test_casr_ubsan/test_ubsan.cpp"),
        abs_path("tests/tmp_tests_casr/test_casr_ubsan/test_ubsan"),
        abs_path("tests/tmp_tests_casr/test_casr_ubsan/input1"),
        abs_path("tests/tmp_tests_casr/test_casr_ubsan/input2"),
        abs_path("tests/tmp_tests_casr/test_casr_ubsan/out"),
    ];

    // Create out dir
    let output = Command::new("mkdir")
        .arg(&paths[4])
        .output()
        .expect("failed to create dir");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=undefined -O0 -g {} -o {} -Wno-everything",
            &paths[0], &paths[1]
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    let output = Command::new(EXE_CASR_UBSAN)
        .args(["--input", &paths[2], &paths[3]])
        .args(["--output", &paths[4]])
        .args(["--", &paths[1], "@@"])
        .output()
        .expect("failed to start casr-ubsan");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res = String::from_utf8_lossy(&output.stderr);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of UBSAN warnings: (?P<casrep>\d+)").unwrap();
    let casrep_cnt = re
        .captures(&res)
        .unwrap()
        .name("casrep")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(casrep_cnt, 6, "Invalid number of warnings");

    let re = Regex::new(r"Number of UBSAN warnings after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&res)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 2, "Invalid number of deduplicated reports");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_libfuzzer() {
    use std::collections::HashMap;

    let paths = [
        abs_path("tests/casr_tests/casrep/libfuzzer_crashes_xlnt"),
        abs_path("tests/tmp_tests_casr/casr_libfuzzer_join"),
        abs_path("tests/tmp_tests_casr/casr_libfuzzer_out"),
        abs_path("tests/casr_tests/bin/load_fuzzer"),
    ];

    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));

    let bins = Path::new(EXE_CASR_LIBFUZZER).parent().unwrap();
    let mut cmd = Command::new(EXE_CASR_LIBFUZZER);
    cmd.args(["-i", &paths[0], "-o", &paths[1], "-f", "--", &paths[3]])
        .env(
            "PATH",
            format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
        );

    let output = cmd.output().expect("failed to start casr-libfuzzer");
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let err = String::from_utf8_lossy(&output.stderr);
    assert!(!err.is_empty());

    assert!(err.contains("casr-san: No crash on input"));
    assert!(err.contains("1 out of memory seeds are saved to"));
    assert!(err.contains("EXPLOITABLE"));
    assert!(err.contains("NOT_EXPLOITABLE"));
    assert!(err.contains("PROBABLY_EXPLOITABLE"));
    assert!(err.contains("heap-buffer-overflow(read)"));
    assert!(err.contains("heap-buffer-overflow(write)"));
    assert!(err.contains("DestAvNearNull"));
    assert!(err.contains("xml::serialization"));
    assert!(err.contains("AbortSignal"));
    assert!(err.contains("compound_document.hpp:83"));

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&err)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 45, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&err)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 23, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));

    // Remove several clusters
    let cluster_paths = [
        abs_path("tests/tmp_tests_casr/casr_libfuzzer_join/cl2"),
        abs_path("tests/tmp_tests_casr/casr_libfuzzer_join/cl20"),
        abs_path("tests/tmp_tests_casr/casr_libfuzzer_join/cl21"),
        abs_path("tests/tmp_tests_casr/casr_libfuzzer_join/cl22"),
        abs_path("tests/tmp_tests_casr/casr_libfuzzer_join/cl23"),
    ];
    for path in cluster_paths {
        let _ = fs::remove_dir_all(path);
    }

    let mut cmd = Command::new(EXE_CASR_LIBFUZZER);
    cmd.args([
        "-i", &paths[0], "--join", &paths[1], "-o", &paths[2], "-f", "--", &paths[3],
    ])
    .env(
        "PATH",
        format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
    );

    let output = cmd.output().expect("failed to start casr-libfuzzer");
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let err = String::from_utf8_lossy(&output.stderr);
    assert!(!err.is_empty());

    assert!(err.contains("casr-san: No crash on input"));
    assert!(err.contains("1 out of memory seeds are saved to"));
    assert!(err.contains("EXPLOITABLE"));
    assert!(err.contains("NOT_EXPLOITABLE"));
    assert!(err.contains("PROBABLY_EXPLOITABLE"));
    assert!(err.contains("heap-buffer-overflow(read)"));
    assert!(err.contains("heap-buffer-overflow(write)"));
    assert!(err.contains("DestAvNearNull"));
    assert!(err.contains("xml::serialization"));
    assert!(err.contains("AbortSignal"));
    assert!(err.contains("compound_document.hpp:83"));

    let re = Regex::new(r"Number of duplicates: (?P<unique>\d+)").unwrap();
    let duplicates_cnt = re
        .captures(&err)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(duplicates_cnt, 28, "Invalid number of duplicates");

    let re = Regex::new(r"Number of new clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&err)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 5, "Invalid number of new clusters");

    let re = Regex::new(r"Number of reports in new clusters: (?P<clusters>\d+)").unwrap();
    let reports_cnt = re
        .captures(&err)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(reports_cnt, 17, "Invalid number of reports in new clusters");

    let re = Regex::new(r"Cluster silhouette score: (?P<score>(0|1)\.\d+)").unwrap();
    let sil_score = re
        .captures(&err)
        .unwrap()
        .name("score")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<f64>()
        .unwrap();

    assert_eq!(
        format!("{sil_score:.2}"),
        "0.38",
        "Invalid cluster silhouette score"
    );

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_libfuzzer_atheris() {
    if lsb_release::info().unwrap().version == "24.04" {
        // Atheris fails to install, see https://github.com/google/atheris/issues/82
        return;
    }
    use std::collections::HashMap;

    let paths = [
        abs_path("tests/casr_tests/casrep/atheris_crashes_ruamel_yaml"),
        abs_path("tests/tmp_tests_casr/casr_libfuzzer_atheris_out"),
        abs_path("tests/tmp_tests_casr/yaml_fuzzer_atheris.py"),
        abs_path("tests/tmp_tests_casr/ruamel"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);
    let _ = fs::remove_file(&paths[2]);
    let _ = fs::remove_dir_all(&paths[3]);
    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));

    fs::copy(
        abs_path("tests/casr_tests/python/yaml_fuzzer_atheris.py"),
        &paths[2],
    )
    .unwrap();

    Command::new("unzip")
        .arg(abs_path("tests/casr_tests/python/ruamel.zip"))
        .current_dir(abs_path("tests/tmp_tests_casr"))
        .stdout(Stdio::null())
        .status()
        .expect("failed to unzip ruamel.zip");

    let bins = Path::new(EXE_CASR_LIBFUZZER).parent().unwrap();
    let mut cmd = Command::new(EXE_CASR_LIBFUZZER);
    cmd.args(["-i", &paths[0], "-o", &paths[1], "--", &paths[2]])
        .env(
            "PATH",
            format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
        );
    let output = cmd.output().expect("failed to start casr-libfuzzer");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let err = String::from_utf8_lossy(&output.stderr);

    assert!(!err.is_empty());

    assert!(err.contains("NOT_EXPLOITABLE"));
    assert!(!err.contains("PROBABLY_EXPLOITABLE"));
    assert!(err.contains("KeyError"));
    assert!(err.contains("TypeError"));
    assert!(err.contains("resolver.py"));
    assert!(err.contains("constructor.py"));

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&err)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 7, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&err)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 2, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_afl_pyafl() {
    use std::collections::HashMap;

    let paths = [
        abs_path("tests/casr_tests/casrep/afl-out-pyafl"),
        abs_path("tests/tmp_tests_casr/casr_afl_pyafl_out"),
        abs_path("tests/tmp_tests_casr/yaml_fuzzer_pyafl.py"),
        abs_path("tests/tmp_tests_casr/ruamel"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);
    let _ = fs::remove_file(&paths[2]);
    let _ = fs::remove_dir_all(&paths[3]);
    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));

    fs::copy(
        abs_path("tests/casr_tests/python/yaml_fuzzer_pyafl.py"),
        &paths[2],
    )
    .unwrap();

    Command::new("unzip")
        .arg(abs_path("tests/casr_tests/python/ruamel.zip"))
        .current_dir(abs_path("tests/tmp_tests_casr"))
        .stdout(Stdio::null())
        .status()
        .expect("failed to unzip ruamel.zip");

    let bins = Path::new(EXE_CASR_AFL).parent().unwrap();
    let mut cmd = Command::new(EXE_CASR_AFL);
    cmd.args(["-i", &paths[0], "-o", &paths[1], "--", &paths[2]])
        .env(
            "PATH",
            format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
        );
    let output = cmd.output().expect("failed to start casr-afl");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let err = String::from_utf8_lossy(&output.stderr);

    assert!(!err.is_empty());

    for crash_type in ["NOT_EXPLOITABLE", "KeyError", "TypeError", "ValueError"] {
        assert!(err.contains(crash_type));
    }

    assert!(err.contains("resolver.py"));
    assert!(err.contains("constructor.py"));

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&err)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 11, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&err)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 5, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_python() {
    // Division by zero test
    let path = abs_path("tests/casr_tests/python/test_casr_python.py");

    let output = Command::new(EXE_CASR_PYTHON)
        .args(["--stdout", "--", &path])
        .output()
        .expect("failed to start casr-python");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(3, report["Stacktrace"].as_array().unwrap().iter().count());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "ZeroDivisionError");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_casr_python.py:4")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_java() {
    let paths = [abs_path("tests/casr_tests/java/Test1.java")];

    // Test only java
    let output = Command::new(EXE_CASR_JAVA)
        .args([
            "--stdout",
            "--",
            "/usr/lib/jvm/java-17-openjdk-amd64/bin/java",
            &paths[0],
        ])
        .output()
        .expect("failed to start casr-java");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(14, report["Stacktrace"].as_array().unwrap().iter().count());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "LowLevelException");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("Test1.java:33")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_java_native_lib() {
    let paths = [
        abs_path("tests/casr_tests/java/Test2.java"),
        abs_path("tests/casr_tests/java/Test2.cpp"),
        abs_path("tests/tmp_tests_casr/libnative.so"),
        abs_path("tests/tmp_tests_casr/"),
    ];

    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));
    // Test java with native lib
    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address -O0 -g -shared \
            -I/usr/lib/jvm/java-17-openjdk-amd64/include \
            -I/usr/lib/jvm/java-17-openjdk-amd64/include/linux \
            -fPIC {} -o {}",
            &paths[1], &paths[2]
        ))
        .output()
        .expect("failed to execute clang++");

    assert!(
        clang.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&clang.stdout),
        String::from_utf8_lossy(&clang.stderr)
    );

    let output = Command::new("bash")
        .arg("-c")
        .arg("clang++ -print-file-name=libclang_rt.asan-x86_64.so")
        .output()
        .expect("failed to execute clang++");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let clang_rt = String::from_utf8_lossy(&output.stdout);
    let cargo_target_dir = PathBuf::from(env!("CARGO_BIN_EXE_casr-san"))
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let output = Command::new(EXE_CASR_JAVA)
        .args([
            "--stdout",
            "--",
            "/usr/lib/jvm/java-17-openjdk-amd64/bin/java",
            &paths[0],
        ])
        .env("CASR_PRELOAD", clang_rt.trim())
        .env("LD_LIBRARY_PATH", &paths[3])
        .env("PATH", format!("{}:{}", env!("PATH"), cargo_target_dir))
        .output()
        .expect("failed to start casr-java");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert!(
            report["Stacktrace"].as_array().unwrap()[0]
                .as_str()
                .unwrap()
                .contains("Java_Test2_heapbufferoverflow")
        );
        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "stack-buffer-overflow(write)");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("Test2.cpp:5")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_python_atheris() {
    if lsb_release::info().unwrap().version == "24.04" {
        // Atheris fails to install, see https://github.com/google/atheris/issues/82
        return;
    }
    // Division by zero atheris test
    let paths = [
        abs_path("tests/casr_tests/python/test_casr_python_atheris.py"),
        abs_path("tests/casr_tests/python/crash"),
    ];

    let output = Command::new(EXE_CASR_PYTHON)
        .args(["--stdout", "--", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-python");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(2, report["Stacktrace"].as_array().unwrap().iter().count());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "ZeroDivisionError");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_casr_python_atheris.py:10")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_san_python_df() {
    if lsb_release::info().unwrap().version == "24.04" {
        // Atheris fails to install, see https://github.com/google/atheris/issues/82
        return;
    }
    // Double free python C extension test
    // Copy files to tmp dir
    let work_dir = abs_path("tests/casr_tests/python");
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_san_python_df");

    let _ = std::fs::remove_dir_all(&test_dir);
    let _ = copy_dir(work_dir, &test_dir).unwrap();

    let paths = [
        abs_path("tests/tmp_tests_casr/test_casr_san_python_df/cpp_module.cpp"),
        abs_path("tests/tmp_tests_casr/test_casr_san_python_df/cpp_module.so"),
        abs_path("tests/tmp_tests_casr/test_casr_san_python_df/test_casr_python_asan_df.py"),
    ];

    let python_path = fs::read_dir("/usr/include")
        .unwrap()
        .filter_map(|s| s.ok())
        .map(|s| s.path())
        .find(|s| s.as_path().to_str().unwrap().contains("python3"));

    if python_path.is_none() {
        panic!("No python include directory is found.");
    }

    let python_path = python_path.unwrap();

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address,fuzzer-no-link -O0 -g {} -o {} -shared -fPIC -I{} -l{}",
            &paths[0],
            &paths[1],
            python_path.display(),
            python_path.file_name().unwrap().to_str().unwrap()
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    // Get path of asan lib
    let output = Command::new("python3")
        .arg("-c")
        .arg("import atheris; print(atheris.path(), end='')")
        .stdout(Stdio::piped())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let lib_path = String::from_utf8_lossy(&output.stdout);
    let lib_path = lib_path + "/asan_with_fuzzer.so";

    assert!(Path::new(&lib_path.to_string()).exists());

    let output = Command::new(EXE_CASR_SAN)
        .env("ASAN_OPTIONS", "detect_leaks=0,symbolize=1")
        .env("CASR_PRELOAD", lib_path.to_string())
        .args(["--stdout", "--", &paths[2]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert!(report["Stacktrace"].as_array().unwrap().iter().count() >= 19);
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "double-free");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("cpp_module.cpp:8:5")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_san_atheris_df() {
    if lsb_release::info().unwrap().version == "24.04" {
        // Atheris fails to install, see https://github.com/google/atheris/issues/82
        return;
    }
    // Double free python C extension test
    // Copy files to tmp dir
    let work_dir = abs_path("tests/casr_tests/python");
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_san_atheris_df");

    let _ = std::fs::remove_dir_all(&test_dir);
    let _ = copy_dir(work_dir, &test_dir).unwrap();

    let paths = [
        abs_path("tests/tmp_tests_casr/test_casr_san_atheris_df/cpp_module.cpp"),
        abs_path("tests/tmp_tests_casr/test_casr_san_atheris_df/cpp_module.so"),
        abs_path(
            "tests/tmp_tests_casr/test_casr_san_atheris_df/test_casr_python_asan_df_atheris.py",
        ),
        abs_path("tests/tmp_tests_casr/test_casr_san_atheris_df/crash"),
    ];

    let python_path = fs::read_dir("/usr/include")
        .unwrap()
        .filter_map(|s| s.ok())
        .map(|s| s.path())
        .find(|s| s.as_path().to_str().unwrap().contains("python3"));

    if python_path.is_none() {
        panic!("No python include directory is found.");
    }

    let python_path = python_path.unwrap();

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address,fuzzer-no-link -O0 -g {} -o {} -shared -fPIC -I{} -l{}",
            &paths[0],
            &paths[1],
            python_path.display(),
            python_path.file_name().unwrap().to_str().unwrap()
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    // Get path of asan lib
    let output = Command::new("python3")
        .arg("-c")
        .arg("import atheris; print(atheris.path(), end='')")
        .stdout(Stdio::piped())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let lib_path = String::from_utf8_lossy(&output.stdout);
    let lib_path = lib_path + "/asan_with_fuzzer.so";

    assert!(Path::new(&lib_path.to_string()).exists());

    let output = Command::new(EXE_CASR_SAN)
        .env("ASAN_OPTIONS", "detect_leaks=0,symbolize=1")
        .env("CASR_PRELOAD", lib_path.to_string())
        .args(["--stdout", "--", &paths[2], &paths[3]])
        .output()
        .expect("failed to start casr-san");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        // TODO: Resolve trouble with asan lib selection
        assert!(report["Stacktrace"].as_array().unwrap().iter().count() > 50);
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "double-free");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("cpp_module.cpp:8:5")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_python_call_san_df() {
    if lsb_release::info().unwrap().version == "24.04" {
        // Atheris fails to install, see https://github.com/google/atheris/issues/82
        return;
    }
    // Double free python C extension test
    // Copy files to tmp dir
    let work_dir = abs_path("tests/casr_tests/python");
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_python_call_san_df");

    let _ = std::fs::remove_dir_all(&test_dir);
    let _ = copy_dir(work_dir, &test_dir).unwrap();

    let paths = [
        abs_path("tests/tmp_tests_casr/test_casr_python_call_san_df/cpp_module.cpp"),
        abs_path("tests/tmp_tests_casr/test_casr_python_call_san_df/cpp_module.so"),
        abs_path("tests/tmp_tests_casr/test_casr_python_call_san_df/test_casr_python_asan_df.py"),
    ];

    let python_path = fs::read_dir("/usr/include")
        .unwrap()
        .filter_map(|s| s.ok())
        .map(|s| s.path())
        .find(|s| s.as_path().to_str().unwrap().contains("python3"));

    if python_path.is_none() {
        panic!("No python include directory is found.");
    }

    let python_path = python_path.unwrap();

    let clang = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "clang++ -fsanitize=address,fuzzer-no-link -O0 -g {} -o {} -shared -fPIC -I{} -l{}",
            &paths[0],
            &paths[1],
            python_path.display(),
            python_path.file_name().unwrap().to_str().unwrap()
        ))
        .status()
        .expect("failed to execute clang++");

    assert!(clang.success());

    // Get path of asan lib
    let output = Command::new("python3")
        .arg("-c")
        .arg("import atheris; print(atheris.path(), end='')")
        .stdout(Stdio::piped())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let lib_path = String::from_utf8_lossy(&output.stdout);
    let lib_path = lib_path + "/asan_with_fuzzer.so";

    assert!(Path::new(&lib_path.to_string()).exists());

    let bins = Path::new(EXE_CASR_PYTHON).parent().unwrap();
    let output = Command::new(EXE_CASR_PYTHON)
        .env("ASAN_OPTIONS", "detect_leaks=0,symolize=1")
        .env("CASR_PRELOAD", lib_path.to_string())
        .env(
            "PATH",
            format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
        )
        .args(["--stdout", "--", &paths[2]])
        .output()
        .expect("failed to start casr-python");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert!(report["Stacktrace"].as_array().unwrap().iter().count() >= 19);
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "double-free");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("cpp_module.cpp:8:5")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[test]
fn test_casr_cluster_c_python() {
    let paths = [
        abs_path("tests/casr_tests/casrep/test_clustering_python"),
        abs_path("tests/tmp_tests_casr/clustering_out_python"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-c", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let res = String::from_utf8_lossy(&output.stdout);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 2, "Clusters count mismatch.");

    let _ = std::fs::remove_dir_all(&paths[1]);
}

#[test]
fn test_casr_cluster_d_python() {
    let paths = [
        abs_path("tests/casr_tests/casrep/test_clustering_python"),
        abs_path("tests/tmp_tests_casr/dedup_out_python"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new(EXE_CASR_CLUSTER)
        .args(["-d", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let dirvec = match fs::read_dir(&paths[1]) {
        Ok(vec) => vec,
        Err(why) => {
            panic!("{:?}", why.kind());
        }
    };

    let counter = dirvec.count();
    if counter != 7 {
        panic!("Bad deduplication, casreps: {counter}");
    }

    let _ = std::fs::remove_dir_all(&paths[1]);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_lua() {
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_lua");
    let test_path = abs_path("tests/casr_tests/lua/test_casr_lua.lua");
    let _ = std::fs::remove_dir_all(test_dir);

    let output = Command::new(EXE_CASR_LUA)
        .args(["--stdout", "--", &test_path])
        .output()
        .expect("failed to start casr-lua");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(6, report["Stacktrace"].as_array().unwrap().iter().count());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "attempt to div a 'string' with a 'number'");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_casr_lua.lua:6")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_js() {
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_js");
    let test_path = abs_path("tests/casr_tests/js/test_casr_js.js");
    let _ = std::fs::remove_dir_all(test_dir);
    let Ok(node_path) = which::which("node") else {
        panic!("No node is found.");
    };

    let output = Command::new(EXE_CASR_JS)
        .args(["--stdout", "--", (node_path.to_str().unwrap()), &test_path])
        .output()
        .expect("failed to start casr-js");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(10, report["Stacktrace"].as_array().unwrap().iter().count());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "Error");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_casr_js.js:3:15")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_js_jsfuzz() {
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_js_jsfuzz");
    let _ = std::fs::remove_dir_all(test_dir);
    let paths = [
        "tests/casr_tests/js/test_casr_js_jsfuzz.js".to_string(),
        "tests/tmp_tests_casr/test_casr_js_jsfuzz/corpus".to_string(),
    ];
    let Ok(jsfuzz_path) = which::which("jsfuzz") else {
        panic!("No jsfuzz is found.");
    };

    // Create out dir
    let output = Command::new("mkdir")
        .args(["-p", &paths[1]])
        .output()
        .expect("failed to create dir");
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut crash_file = fs::File::create(abs_path(
        "tests/tmp_tests_casr/test_casr_js_jsfuzz/corpus/crash",
    ))
    .unwrap();
    crash_file.write_all(b"AAAAAAAAAAAAAAAAAAAAAAAA").unwrap();

    let output = Command::new(EXE_CASR_JS)
        .args([
            "--stdout",
            "--",
            (jsfuzz_path.to_str().unwrap()),
            &paths[0],
            &paths[1],
        ])
        .output()
        .expect("failed to start casr-js");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(10, report["Stacktrace"].as_array().unwrap().iter().count());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "Error");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_casr_js_jsfuzz.js:2:15")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_js_jazzer() {
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_js_jazzer");
    let _ = std::fs::remove_dir_all(test_dir);
    let paths = [
        abs_path("tests/casr_tests/js/test_casr_js_jazzer.js"),
        abs_path("tests/tmp_tests_casr/test_casr_js_jazzer/corpus"),
    ];
    let Ok(npx_path) = which::which("npx") else {
        panic!("No npx is found.");
    };

    // Create out dir
    let output = Command::new("mkdir")
        .args(["-p", &paths[1]])
        .output()
        .expect("failed to create dir");
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut crash_file = fs::File::create(abs_path(
        "tests/tmp_tests_casr/test_casr_js_jazzer/corpus/crash",
    ))
    .unwrap();
    crash_file.write_all(b"AAAAAAAAAAAAAAAAAAAAAAAA").unwrap();

    let output = Command::new(EXE_CASR_JS)
        .args([
            "--stdout",
            "--",
            (npx_path.to_str().unwrap()),
            "jazzer",
            &paths[0],
            &paths[1],
        ])
        .output()
        .expect("failed to start casr-js");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(5, report["Stacktrace"].as_array().unwrap().iter().count());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "Error");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_casr_js_jazzer.js:3:15")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_js_native() {
    // JS C extension test
    // Copy files to tmp dir
    let work_dir = abs_path("tests/casr_tests/js");
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_js_native");

    let _ = std::fs::remove_dir_all(&test_dir);
    let _ = copy_dir(work_dir, &test_dir).unwrap();

    let paths = [
        abs_path("tests"),
        abs_path("tests/tmp_tests_casr/test_casr_js_native"),
        abs_path("tests/tmp_tests_casr/test_casr_js_native/test_casr_js_native.js"),
    ];

    let Ok(npm_path) = which::which("npm") else {
        panic!("No npm is found.");
    };

    let mut npm = Command::new(&npm_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .current_dir(&paths[1])
        .env("CC", "clang")
        .env("CXX", "clang++")
        .arg("init")
        .arg("-y")
        .spawn()
        .expect("failed to run npm init");

    let mut stdin = npm.stdin.take().expect("failed to open stdin");
    stdin
        .write_all("\n\n\n\n\n\n\n\n".as_bytes())
        .expect("failed to write to stdin");

    npm.wait().expect("failed to run npm init");

    let npm = Command::new("bash")
        .current_dir(&paths[1])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg("-c")
        .arg(format!(
            "{} install node-addon-api bindings",
            &npm_path.display()
        ))
        .status()
        .expect("failed to add node-addon-api bindings");
    assert!(npm.success());

    let npm = Command::new("bash")
        .current_dir(&paths[1])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env("CC", "clang")
        .env("CXX", "clang++")
        .arg("-c")
        .arg(format!("{} install {}", &npm_path.display(), &paths[1]))
        .status()
        .expect("failed to run npm install");
    assert!(npm.success());

    // Get path of asan lib
    let output = Command::new("bash")
        .arg("-c")
        .arg("clang++ -print-file-name=libclang_rt.asan-x86_64.so")
        .output()
        .expect("failed to execute clang++");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let clang_rt = String::from_utf8_lossy(&output.stdout);
    assert!(Path::new(&clang_rt.trim().to_string()).exists());

    let Ok(node_path) = which::which("node") else {
        panic!("No node is found.");
    };

    let output = Command::new(EXE_CASR_JS)
        .env("ASAN_OPTIONS", "detect_leaks=0,symbolize=1")
        .env("CASR_PRELOAD", clang_rt.trim())
        .env(
            "LD_LIBRARY_PATH",
            Path::new(&clang_rt.trim().to_string())
                .parent()
                .unwrap_or(Path::new("")),
        )
        .args(["--stdout", "--", node_path.to_str().unwrap(), &paths[2]])
        .output()
        .expect("failed to start casr-js");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert!(report["Stacktrace"].as_array().unwrap().iter().count() >= 4);
        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "stack-buffer-overflow(write)");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("native.cpp:9:13")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_js_native_jsfuzz() {
    // JS jsfuzz C extension test
    // Copy files to tmp dir
    let work_dir = abs_path("tests/casr_tests/js");
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_js_native_jsfuzz");

    let _ = std::fs::remove_dir_all(&test_dir);
    let _ = copy_dir(work_dir, &test_dir).unwrap();

    let paths = [
        abs_path("tests"),
        abs_path("tests/tmp_tests_casr/test_casr_js_native_jsfuzz"),
        "tests/tmp_tests_casr/test_casr_js_native_jsfuzz/test_casr_js_native_jsfuzz.js".to_string(),
    ];

    let Ok(npm_path) = which::which("npm") else {
        panic!("No npm is found.");
    };

    let mut npm = Command::new(&npm_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .current_dir(&paths[1])
        .env("CC", "clang")
        .env("CXX", "clang++")
        .arg("init")
        .arg("-y")
        .spawn()
        .expect("failed to run npm init");

    let mut stdin = npm.stdin.take().expect("failed to open stdin");
    stdin
        .write_all("\n\n\n\n\n\n\n\n".as_bytes())
        .expect("failed to write to stdin");

    npm.wait().expect("failed to run npm init");

    let npm = Command::new("bash")
        .current_dir(&paths[1])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg("-c")
        .arg(format!(
            "{} install node-addon-api bindings",
            &npm_path.display()
        ))
        .status()
        .expect("failed to add node-addon-api bindings");
    assert!(npm.success());

    let npm = Command::new("bash")
        .current_dir(&paths[1])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env("CC", "clang")
        .env("CXX", "clang++")
        .arg("-c")
        .arg(format!("{} install {}", &npm_path.display(), &paths[1]))
        .status()
        .expect("failed to run npm install");
    assert!(npm.success());

    // Get path of asan lib
    let output = Command::new("bash")
        .arg("-c")
        .arg("clang++ -print-file-name=libclang_rt.asan-x86_64.so")
        .output()
        .expect("failed to execute clang++");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let clang_rt = String::from_utf8_lossy(&output.stdout);
    assert!(Path::new(&clang_rt.trim().to_string()).exists());

    let Ok(jsfuzz_path) = which::which("jsfuzz") else {
        panic!("No jsfuzz is found.");
    };

    let output = Command::new(EXE_CASR_JS)
        .env("ASAN_OPTIONS", "detect_leaks=0,symbolize=1")
        .env("CASR_PRELOAD", clang_rt.trim())
        .env(
            "LD_LIBRARY_PATH",
            Path::new(&clang_rt.trim().to_string())
                .parent()
                .unwrap_or(Path::new("")),
        )
        .args(["--stdout", "--", jsfuzz_path.to_str().unwrap(), &paths[2]])
        .output()
        .expect("failed to start casr-js");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert!(report["Stacktrace"].as_array().unwrap().iter().count() >= 4);
        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "stack-buffer-overflow(write)");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("native.cpp:9:13")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_js_native_jazzer() {
    // JS jsfuzz C extension test
    // Copy files to tmp dir
    let work_dir = abs_path("tests/casr_tests/js");
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_js_native_jazzer");

    let _ = std::fs::remove_dir_all(&test_dir);
    let _ = copy_dir(work_dir, &test_dir).unwrap();

    let paths = [
        abs_path("tests"),
        abs_path("tests/tmp_tests_casr/test_casr_js_native_jazzer"),
        abs_path("tests/tmp_tests_casr/test_casr_js_native_jazzer/test_casr_js_native_jazzer.js"),
    ];

    let Ok(npm_path) = which::which("npm") else {
        panic!("No npm is found.");
    };

    let mut npm = Command::new(&npm_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .current_dir(&paths[1])
        .env("CC", "clang")
        .env("CXX", "clang++")
        .arg("init")
        .arg("-y")
        .spawn()
        .expect("failed to run npm init");

    let mut stdin = npm.stdin.take().expect("failed to open stdin");
    stdin
        .write_all("\n\n\n\n\n\n\n\n".as_bytes())
        .expect("failed to write to stdin");

    npm.wait().expect("failed to run npm init");

    let npm = Command::new("bash")
        .current_dir(&paths[1])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg("-c")
        .arg(format!(
            "{} install node-addon-api bindings",
            &npm_path.display()
        ))
        .status()
        .expect("failed to add node-addon-api bindings");
    assert!(npm.success());

    let npm = Command::new("bash")
        .current_dir(&paths[1])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env("CC", "clang")
        .env("CXX", "clang++")
        .arg("-c")
        .arg(format!("{} install {}", &npm_path.display(), &paths[1]))
        .status()
        .expect("failed to run npm install");
    assert!(npm.success());

    // Get path of asan lib
    let output = Command::new("bash")
        .arg("-c")
        .arg("clang++ -print-file-name=libclang_rt.asan-x86_64.so")
        .output()
        .expect("failed to execute clang++");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let clang_rt = String::from_utf8_lossy(&output.stdout);
    assert!(Path::new(&clang_rt.trim().to_string()).exists());

    let Ok(npx_path) = which::which("npx") else {
        panic!("No npx is found.");
    };

    let output = Command::new(EXE_CASR_JS)
        .env("ASAN_OPTIONS", "detect_leaks=0,symbolize=1")
        .env("CASR_PRELOAD", clang_rt.trim())
        .env(
            "LD_LIBRARY_PATH",
            Path::new(&clang_rt.trim().to_string())
                .parent()
                .unwrap_or(Path::new("")),
        )
        .args([
            "--stdout",
            "--",
            npx_path.to_str().unwrap(),
            "jazzer",
            &paths[2],
        ])
        .output()
        .expect("failed to start casr-js");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert!(report["Stacktrace"].as_array().unwrap().iter().count() >= 4);
        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "stack-buffer-overflow(write)");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("native.cpp:9:13")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

// Jsfuzz is available only in very old version and it behaves very strangely.
// Launching jsfuzz on a simple example doesn't work correctly, so this test
// also produces very strange results.
// There are problems in updating jsfuzz to the newer version due to its moving
// to gitlab (they have several open issues about it).
#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_libfuzzer_jsfuzz() {
    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_libfuzzer_jsfuzz");
    let _ = std::fs::remove_dir_all(test_dir);
    let paths = [
        "tests/casr_tests/js/test_casr_libfuzzer_jsfuzz.js".to_string(),
        abs_path("tests/tmp_tests_casr/test_casr_libfuzzer_jsfuzz/crashes"),
        abs_path("tests/tmp_tests_casr/test_casr_libfuzzer_jsfuzz/casr_out"),
        "tests/tmp_tests_casr/test_casr_libfuzzer_jsfuzz/test_casr_libfuzzer_jsfuzz.js".to_string(),
    ];

    // Create crashes dir
    let output = Command::new("mkdir")
        .args(["-p", &paths[1]])
        .output()
        .expect("failed to create dir");
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::copy(&paths[0], &paths[3]);

    let Ok(jsfuzz_path) = which::which("jsfuzz") else {
        panic!("No jsfuzz is found.");
    };

    Command::new("unzip")
        .arg(abs_path("tests/casr_tests/js/crashes.zip"))
        .args(["-d", &paths[1]])
        .stdout(Stdio::null())
        .status()
        .expect("failed to unzip crashes.zip");

    let bins = Path::new(EXE_CASR_LIBFUZZER).parent().unwrap();
    let mut cmd = Command::new(EXE_CASR_LIBFUZZER);
    cmd.args([
        "-i",
        &paths[1],
        "-o",
        &paths[2],
        "--",
        jsfuzz_path.to_str().unwrap(),
        &paths[3],
    ])
    .env(
        "PATH",
        format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
    );
    let output = cmd.output().expect("failed to start casr-libfuzzer");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let err = String::from_utf8_lossy(&output.stderr);

    assert!(!err.is_empty());

    assert!(err.contains("NOT_EXPLOITABLE"));
    assert!(err.contains("Error"));
    assert!(err.contains("test_casr_libfuzzer_jsfuzz.js"));

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&err)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 1, "Invalid number of deduplicated reports");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_libfuzzer_jazzer_js() {
    use std::collections::HashMap;

    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_libfuzzer_jazzer_js");
    let _ = std::fs::remove_dir_all(test_dir);
    let paths = [
        abs_path("tests/casr_tests/js/test_casr_libfuzzer_jazzer_js.js"),
        abs_path("tests/tmp_tests_casr/test_casr_libfuzzer_jazzer_js/crashes"),
        abs_path("tests/tmp_tests_casr/test_casr_libfuzzer_jazzer_js/casr_out"),
        abs_path(
            "tests/tmp_tests_casr/test_casr_libfuzzer_jazzer_js/test_casr_libfuzzer_jazzer_js.js",
        ),
    ];

    // Create crashes dir
    let output = Command::new("mkdir")
        .args(["-p", &paths[1]])
        .output()
        .expect("failed to create dir");
    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::copy(&paths[0], &paths[3]);

    let Ok(npx_path) = which::which("npx") else {
        panic!("No npx is found.");
    };

    Command::new("unzip")
        .arg(abs_path("tests/casr_tests/js/crashes.zip"))
        .args(["-d", &paths[1]])
        .stdout(Stdio::null())
        .status()
        .expect("failed to unzip crashes.zip");

    let bins = Path::new(EXE_CASR_LIBFUZZER).parent().unwrap();
    let mut cmd = Command::new(EXE_CASR_LIBFUZZER);
    cmd.args([
        "-i",
        &paths[1],
        "-o",
        &paths[2],
        "--",
        npx_path.to_str().unwrap(),
        "jazzer",
        &paths[3],
    ])
    .env(
        "PATH",
        format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
    );
    let output = cmd.output().expect("failed to start casr-libfuzzer");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let err = String::from_utf8_lossy(&output.stderr);

    assert!(!err.is_empty());

    assert!(err.contains("NOT_EXPLOITABLE"));
    assert!(err.contains("TypeError"));
    assert!(err.contains("ReferenceError"));
    assert!(err.contains("RangeError"));
    assert!(err.contains("test_casr_libfuzzer_jazzer_js.js"));

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&err)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 3, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&err)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 1, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[2]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_libfuzzer_jazzer_js_xml2js() {
    use std::collections::HashMap;

    let test_dir = abs_path("tests/tmp_tests_casr/test_casr_libfuzzer_jazzer_js_xml2js");
    let _ = std::fs::remove_dir_all(&test_dir);
    let paths = [
        abs_path("tests/casr_tests/js/test_casr_libfuzzer_jazzer_js_xml2js.js"),
        abs_path("tests/tmp_tests_casr/test_casr_libfuzzer_jazzer_js_xml2js/crashes"),
        abs_path("tests/tmp_tests_casr/test_casr_libfuzzer_jazzer_js_xml2js/casr_out"),
        abs_path(
            "tests/tmp_tests_casr/test_casr_libfuzzer_jazzer_js_xml2js/test_casr_libfuzzer_jazzer_js_xml2js.js",
        ),
    ];

    // Create crashes dir
    let output = Command::new("mkdir")
        .args(["-p", &paths[1]])
        .output()
        .expect("failed to create dir");
    assert!(
        output.status.success(),
        "Stdout: {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::copy(&paths[0], &paths[3]);

    Command::new("unzip")
        .arg(abs_path("tests/casr_tests/js/xml2js.zip"))
        .args(["-d", &paths[1]])
        .stdout(Stdio::null())
        .status()
        .expect("failed to unzip xml2js.zip");

    let Ok(npm_path) = which::which("npm") else {
        panic!("No npm is found.");
    };

    let mut npm = Command::new(&npm_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .current_dir(&test_dir)
        .env("CC", "clang")
        .env("CXX", "clang++")
        .arg("init")
        .arg("-y")
        .spawn()
        .expect("failed to run npm init");

    let mut stdin = npm.stdin.take().expect("failed to open stdin");
    stdin
        .write_all("\n\n\n\n\n\n\n\n".as_bytes())
        .expect("failed to write to stdin");

    npm.wait().expect("failed to run npm init");

    let npm = Command::new("bash")
        .current_dir(&test_dir)
        .arg("-c")
        .arg(format!("{} install xml2js", &npm_path.display()))
        .output()
        .expect("failed to install xml2js");
    assert!(
        npm.status.success(),
        "Stdout: {}.\n Stderr: {}",
        String::from_utf8_lossy(&npm.stdout),
        String::from_utf8_lossy(&npm.stderr)
    );

    let Ok(npx_path) = which::which("npx") else {
        panic!("No npx is found.");
    };

    let bins = Path::new(EXE_CASR_LIBFUZZER).parent().unwrap();
    let mut cmd = Command::new(EXE_CASR_LIBFUZZER);
    cmd.args([
        "-i",
        &paths[1],
        "-o",
        &paths[2],
        "--",
        npx_path.to_str().unwrap(),
        "jazzer",
        &paths[3],
    ])
    .env(
        "PATH",
        format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
    );
    let output = cmd.output().expect("failed to start casr-libfuzzer");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let err = String::from_utf8_lossy(&output.stderr);

    assert!(!err.is_empty());

    assert!(err.contains("NOT_EXPLOITABLE"));
    assert!(err.contains("TypeError"));
    assert!(err.contains("xml2js/lib/parser.js"));
    assert!(err.contains("Error"));
    assert!(err.contains("sax/lib/sax.js"));

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&err)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 3, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&err)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 2, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[2]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_csharp() {
    let paths = [
        abs_path("tests/casr_tests/csharp/test_casr_csharp/test_casr_csharp.cs"),
        abs_path("tests/casr_tests/csharp/test_casr_csharp/test_casr_csharp.csproj"),
        abs_path("tests/tmp_tests_casr/test_casr_csharp"),
        abs_path("tests/tmp_tests_casr/test_casr_csharp/test_casr_csharp.cs"),
        abs_path("tests/tmp_tests_casr/test_casr_csharp/test_casr_csharp.csproj"),
    ];
    let _ = std::fs::create_dir_all(&paths[2]);
    let _ = fs::copy(&paths[0], &paths[3]);
    let _ = fs::copy(&paths[1], &paths[4]);
    let Ok(dotnet_path) = which::which("dotnet") else {
        panic!("No dotnet is found.");
    };

    let output = Command::new(EXE_CASR_CSHARP)
        .args([
            "--stdout",
            "--",
            (dotnet_path.to_str().unwrap()),
            "run",
            "--project",
            &paths[4],
        ])
        .output()
        .expect("failed to start casr-csharp");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(3, report["Stacktrace"].as_array().unwrap().iter().count());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "System.ArgumentException");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_casr_csharp.cs:14")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_csharp_native() {
    let paths = [
        abs_path("tests/casr_tests/csharp/test_casr_csharp_native/test_casr_csharp_native.cs"),
        abs_path("tests/casr_tests/csharp/test_casr_csharp_native/test_casr_csharp_native.csproj"),
        abs_path("tests/casr_tests/csharp/test_casr_csharp_native/native.cpp"),
        abs_path("tests/tmp_tests_casr/test_casr_csharp_native"),
        abs_path("tests/tmp_tests_casr/test_casr_csharp_native/test_casr_csharp_native.cs"),
        abs_path("tests/tmp_tests_casr/test_casr_csharp_native/test_casr_csharp_native.csproj"),
        abs_path("tests/tmp_tests_casr/test_casr_csharp_native/native.so"),
    ];
    let _ = std::fs::create_dir_all(&paths[3]);
    let _ = fs::copy(&paths[0], &paths[4]);
    let _ = fs::copy(&paths[1], &paths[5]);
    let Ok(dotnet_path) = which::which("dotnet") else {
        panic!("No dotnet is found.");
    };

    let _ = Command::new("clang++")
        .args([&paths[2], "-g", "-fPIC", "-shared", "-o", &paths[6]])
        .output()
        .expect("failed to compile .so library");

    let _ = Command::new("dotnet")
        .args(["build", &paths[5]])
        .output()
        .expect("failed to build test");

    let output = Command::new(EXE_CASR_CSHARP)
        .args([
            "--stdout",
            "--",
            (dotnet_path.to_str().unwrap()),
            format!("{}/bin/Debug/net8.0/test_casr_csharp_native.dll", &paths[3]).as_str(),
        ])
        .env("LD_LIBRARY_PATH", &paths[3])
        .output()
        .expect("failed to start casr-csharp");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Result<Value, _> = serde_json::from_slice(&output.stdout);
    if let Ok(report) = report {
        let severity_type = report["CrashSeverity"]["Type"].as_str().unwrap();
        let severity_desc = report["CrashSeverity"]["ShortDescription"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(
            19 + (lsb_release::info().unwrap().version == "24.04") as usize,
            report["Stacktrace"].as_array().unwrap().iter().count()
        );
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "AccessViolation");
        assert!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("native.cpp:6")
        );
    } else {
        panic!("Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_afl_csharp() {
    use std::collections::HashMap;

    let paths = [
        abs_path("tests/casr_tests/casrep/afl-out-sharpfuzz"),
        abs_path("tests/tmp_tests_casr/casr_afl_csharp_out"),
        abs_path("tests/casr_tests/csharp/test_casr_afl_csharp"),
        abs_path("tests/casr_tests/csharp/test_casr_afl_csharp_module"),
        abs_path("/tmp/test_casr_afl_csharp"),
        abs_path("/tmp/test_casr_afl_csharp_module"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);
    let _ = fs::remove_dir_all(&paths[4]);
    let _ = fs::remove_dir_all(&paths[5]);
    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));
    let _ = copy_dir(&paths[2], &paths[4]).unwrap();
    let _ = copy_dir(&paths[3], &paths[5]).unwrap();
    let Ok(dotnet_path) = which::which("dotnet") else {
        panic!("No dotnet is found.");
    };

    let _ = Command::new(dotnet_path.to_str().unwrap())
        .args([
            "publish",
            "-o",
            &format!("{}/bin", &paths[4]),
            &format!("{}/test_casr_afl_csharp.csproj", &paths[4]),
        ])
        .output()
        .expect("dotnet publish crashed");

    let bins = Path::new(EXE_CASR_AFL).parent().unwrap();
    let mut output = Command::new(EXE_CASR_AFL);
    output.args(["-i", &paths[0], "-o", &paths[1]]).env(
        "PATH",
        format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
    );

    let output = output.output().expect("casr-afl crashed");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let res = String::from_utf8_lossy(&output.stderr);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&res)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 3, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 3, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));
    let _ = fs::remove_dir_all(&paths[4]);
    let _ = fs::remove_dir_all(&paths[5]);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_afl_csharp_ignore_cmd() {
    use std::collections::HashMap;

    let paths = [
        abs_path("tests/casr_tests/casrep/afl-out-sharpfuzz"),
        abs_path("tests/tmp_tests_casr/casr_afl_csharp_ignore_cmd_out"),
        abs_path("tests/casr_tests/csharp/test_casr_afl_csharp"),
        abs_path("tests/casr_tests/csharp/test_casr_afl_csharp_module"),
        abs_path("/tmp/casr_afl_csharp_ignore_cmd/test_casr_afl_csharp"),
        abs_path("/tmp/casr_afl_csharp_ignore_cmd/test_casr_afl_csharp_module"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);
    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));
    let _ = fs::create_dir_all("/tmp/casr_afl_csharp_ignore_cmd");
    let _ = copy_dir(&paths[2], &paths[4]).unwrap();
    let _ = copy_dir(&paths[3], &paths[5]).unwrap();
    let Ok(dotnet_path) = which::which("dotnet") else {
        panic!("No dotnet is found.");
    };

    let _ = Command::new(dotnet_path.to_str().unwrap())
        .args([
            "build",
            &format!("{}/test_casr_afl_csharp.csproj", &paths[4]),
        ])
        .output()
        .expect("dotnet build crashed");

    let bins = Path::new(EXE_CASR_AFL).parent().unwrap();
    let mut output = Command::new(EXE_CASR_AFL);
    output
        .args([
            "--ignore-cmdline",
            "-i",
            &paths[0],
            "-o",
            &paths[1],
            "--",
            (dotnet_path.to_str().unwrap()),
            "run",
            "--no-build",
            "--project",
            &format!("{}/test_casr_afl_csharp.csproj", &paths[4]),
            "@@",
        ])
        .env(
            "PATH",
            format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
        );

    let output = output.output().expect("casr-afl crashed");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let res = String::from_utf8_lossy(&output.stderr);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&res)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 3, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 3, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));
    let _ = fs::remove_dir_all("/tmp/casr_afl_csharp_ignore_cmd");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_afl_csharp_vanilla_afl() {
    use std::collections::HashMap;

    let paths = [
        abs_path("tests/casr_tests/casrep/afl-out-sharpfuzz/afl_main-worker"),
        abs_path("tests/tmp_tests_casr/casr_afl_csharp_vanilla_afl_out"),
        abs_path("tests/casr_tests/csharp/test_casr_afl_csharp"),
        abs_path("tests/casr_tests/csharp/test_casr_afl_csharp_module"),
        abs_path("/tmp/casr_afl_csharp_vanilla/test_casr_afl_csharp"),
        abs_path("/tmp/casr_afl_csharp_vanilla/test_casr_afl_csharp_module"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);
    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));
    let _ = fs::create_dir_all("/tmp/casr_afl_csharp_vanilla");
    let _ = copy_dir(&paths[2], &paths[4]).unwrap();
    let _ = copy_dir(&paths[3], &paths[5]).unwrap();
    let Ok(dotnet_path) = which::which("dotnet") else {
        panic!("No dotnet is found.");
    };

    let _ = Command::new(dotnet_path.to_str().unwrap())
        .args([
            "build",
            &format!("{}/test_casr_afl_csharp.csproj", &paths[4]),
        ])
        .output()
        .expect("dotnet build crashed");

    let bins = Path::new(EXE_CASR_AFL).parent().unwrap();
    let mut output = Command::new(EXE_CASR_AFL);
    output
        .args([
            "-i",
            &paths[0],
            "-o",
            &paths[1],
            "--",
            (dotnet_path.to_str().unwrap()),
            "run",
            "--no-build",
            "--project",
            &format!("{}/test_casr_afl_csharp.csproj", &paths[4]),
            "@@",
        ])
        .env(
            "PATH",
            format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
        );

    let output = output.output().expect("casr-afl crashed");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let res = String::from_utf8_lossy(&output.stderr);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&res)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 3, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 3, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x > 1));
    let _ = fs::remove_dir_all("/tmp/casr_afl_csharp_vanilla");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_libfuzzer_libafl() {
    use std::collections::HashMap;

    let paths = [
        abs_path("tests/casr_tests/casrep/test_libafl_crashes"),
        abs_path("tests/tmp_tests_casr/casr_libafl_out"),
    ];

    let _ = fs::remove_dir_all(&paths[1]);
    let _ = fs::create_dir(abs_path("tests/tmp_tests_casr"));
    let _ = fs::copy(
        abs_path("tests/casr_tests/bin/test_libafl_fuzzer"),
        "/tmp/test_libafl_fuzzer",
    );

    let bins = Path::new(EXE_CASR_LIBFUZZER).parent().unwrap();
    let output = Command::new(EXE_CASR_LIBFUZZER)
        .args([
            "-i",
            &paths[0],
            "-o",
            &paths[1],
            "--",
            "/tmp/test_libafl_fuzzer",
            "@@",
        ])
        .env(
            "PATH",
            format!("{}:{}", bins.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .expect("failed to start casr-libfuzzer");

    assert!(
        output.status.success(),
        "Stdout {}.\n Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let res = String::from_utf8_lossy(&output.stderr);

    assert!(!res.is_empty());

    let re = Regex::new(r"Number of reports after deduplication: (?P<unique>\d+)").unwrap();
    let unique_cnt = re
        .captures(&res)
        .unwrap()
        .name("unique")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(unique_cnt, 5, "Invalid number of deduplicated reports");

    let re = Regex::new(r"Number of clusters: (?P<clusters>\d+)").unwrap();
    let clusters_cnt = re
        .captures(&res)
        .unwrap()
        .name("clusters")
        .map(|x| x.as_str())
        .unwrap()
        .parse::<u32>()
        .unwrap();

    assert_eq!(clusters_cnt, 5, "Invalid number of clusters");

    let mut storage: HashMap<String, u32> = HashMap::new();
    for entry in fs::read_dir(&paths[1]).unwrap() {
        let e = entry.unwrap().path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            for file in fs::read_dir(e).unwrap() {
                let mut e = file.unwrap().path();
                if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
                    e = e.with_extension("");
                    if e.extension().is_some() && e.extension().unwrap() == "gdb" {
                        e = e.with_extension("");
                    }
                }
                let fname = e.file_name().unwrap().to_str().unwrap();
                if let Some(v) = storage.get_mut(fname) {
                    *v += 1;
                } else {
                    storage.insert(fname.to_string(), 1);
                }
            }
        }
    }

    assert!(storage.values().all(|x| *x == 2));
    let _ = fs::remove_file("/tmp/test_libafl_fuzzer");
    let _ = fs::remove_dir_all(&paths[1]);
}
