extern crate lazy_static;
extern crate regex;
extern crate serde_json;

use regex::Regex;
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::RwLock;

lazy_static::lazy_static! {
    pub static ref EXE_DIR: RwLock<PathBuf> = RwLock::new( match std::env::current_exe() {
        Ok(cur_exe) => match cur_exe.parent() {
                    Some(cur_dir) => {
                                    match cur_dir.parent() {
                                        Some(parent) => parent.to_path_buf(),
                                        None =>  PathBuf::from(".."),
                                    }
                                    },
                    None => PathBuf::from(".."),
                   }
        Err(_) => PathBuf::from(".."),
    });
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_segfault_on_pc() {
    let paths = [
        "tests/casr_tests/core.test_segFaultOnPc",
        "tests/casr_tests/test_segFaultOnPc",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av() {
    let paths = [
        "tests/casr_tests/core.test_destAv",
        "tests/casr_tests/test_destAv",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_near_null() {
    let paths = [
        "tests/casr_tests/core.test_destAvNearNull",
        "tests/casr_tests/test_destAvNearNull",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}
#[test]
#[cfg(target_arch = "x86_64")]
fn test_return_av() {
    let paths = [
        "tests/casr_tests/core.test_returnAv",
        "tests/casr_tests/test_returnAv",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av() {
    let paths = [
        "tests/casr_tests/core.test_callAv",
        "tests/casr_tests/test_callAv",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av_tainted() {
    let paths = [
        "tests/casr_tests/core.test_callAvTainted",
        "tests/casr_tests/test_callAvTainted",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av() {
    let paths = [
        "tests/casr_tests/core.test_sourceAv",
        "tests/casr_tests/test_sourceAv",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_near_null() {
    let paths = [
        "tests/casr_tests/core.test_sourceAvNearNull",
        "tests/casr_tests/test_sourceAvNearNull",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_abort() {
    let paths = [
        "tests/casr_tests/core.test_abort",
        "tests/casr_tests/test_abort",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[ignore]
#[cfg(target_arch = "x86_64")]
fn test_canary() {
    let paths = [
        "tests/casr_tests/core.test_canary",
        "tests/casr_tests/test_canary",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[ignore]
#[cfg(target_arch = "x86_64")]
fn test_safe_func() {
    let paths = [
        "tests/casr_tests/core.test_safeFunc",
        "tests/casr_tests/test_safeFunc",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_bad_instruction() {
    let paths = [
        "tests/casr_tests/core.test_badInstruction",
        "tests/casr_tests/test_badInstruction",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_stack_overflow() {
    let paths = [
        "tests/casr_tests/core.test_stackOverflow",
        "tests/casr_tests/test_stackOverflow",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_tainted() {
    let paths = [
        "tests/casr_tests/core.test_destAvTainted",
        "tests/casr_tests/test_destAvTainted",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_div_by_zero() {
    let paths = [
        "tests/casr_tests/core.test_DivByZero",
        "tests/casr_tests/test_DivByZero",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_segfault_on_pc32() {
    let paths = [
        "tests/casr_tests/core.test_segFaultOnPc32",
        "tests/casr_tests/test_segFaultOnPc32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av32() {
    let paths = [
        "tests/casr_tests/core.test_destAv32",
        "tests/casr_tests/test_destAv32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_near_null32() {
    let paths = [
        "tests/casr_tests/core.test_destAvNearNull32",
        "tests/casr_tests/test_destAvNearNull32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_return_av32() {
    let paths = [
        "tests/casr_tests/core.test_returnAv32",
        "tests/casr_tests/test_returnAv32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av32() {
    let paths = [
        "tests/casr_tests/core.test_callAv32",
        "tests/casr_tests/test_callAv32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av32() {
    let paths = [
        "tests/casr_tests/core.test_sourceAv32",
        "tests/casr_tests/test_sourceAv32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_near_null32() {
    let paths = [
        "tests/casr_tests/core.test_sourceAvNearNull32",
        "tests/casr_tests/test_sourceAvNearNull32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_abort32() {
    let paths = [
        "tests/casr_tests/core.test_abort32",
        "tests/casr_tests/test_abort32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[ignore]
#[cfg(target_arch = "x86_64")]
fn test_canary32() {
    let paths = [
        "tests/casr_tests/core.test_canary32",
        "tests/casr_tests/test_canary32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[ignore]
#[cfg(target_arch = "x86_64")]
fn test_safe_func32() {
    let paths = [
        "tests/casr_tests/core.test_safeFunc32",
        "tests/casr_tests/test_safeFunc32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_bad_instruction32() {
    let paths = [
        "tests/casr_tests/core.test_badInstruction32",
        "tests/casr_tests/test_badInstruction32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_div_by_zero32() {
    let paths = [
        "tests/casr_tests/core.test_DivByZero32",
        "tests/casr_tests/test_DivByZero32",
    ];
    // Run casr.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr"))
        .args(&["-f", &paths[0], "-e", &paths[1], "--stdout"])
        .output()
        .expect("failed to start casr");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_abort_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&["--stdout", "--", "tests/casr_tests/test_abort", "A"])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_segfault_on_pc_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_segFaultOnPc",
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_destAv",
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_near_null_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_destAvNearNull",
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_return_av_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_returnAv",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_callAv",
            "-11111111",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av_tainted_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_callAvTainted",
            "-11111111",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_sourceAv",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_near_null_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_sourceAvNearNull",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_canary_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_canary",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_safe_func_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_safeFunc",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_bad_instruction_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_badInstruction",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_stack_overflow_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_stackOverflow",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_tainted_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_destAvTainted",
            "-111111111",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_div_by_zero_gdb() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&["--stdout", "--", "tests/casr_tests/test_DivByZero"])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_abort_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&["--stdout", "--", "tests/casr_tests/test_abort32", "A"])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_segfault_on_pc_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_segFaultOnPc32",
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_destAv32",
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dest_av_near_null_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_destAvNearNull32",
            &(0..125).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_return_av_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_returnAv32",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_call_av_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_callAv32",
            "-11111111",
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_sourceAv32",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_source_av_near_null_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_sourceAvNearNull32",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_canary_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_canary32",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_safe_func_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_safeFunc32",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_bad_instruction_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&[
            "--stdout",
            "--",
            "tests/casr_tests/test_badInstruction32",
            &(0..150).map(|_| "A").collect::<String>(),
        ])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_div_by_zero_gdb32() {
    // Run casr-gdb.
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-gdb"))
        .args(&["--stdout", "--", "tests/casr_tests/test_DivByZero32"])
        .output()
        .expect("failed to start casr-gdb");

    // Test if casr got results.
    assert!(output.status.success());

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
        assert!(false, "Couldn't parse json report file.");
    }
}

#[test]
fn test_casr_cluster_s() {
    let paths = [
        "tests/casr_tests/casrep/test1/3.casrep",
        "tests/casr_tests/casrep/test1/4.casrep",
    ];
    let mut output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-cluster"))
        .args(&["-s", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(output.status.success());

    let res: f64 = output
        .stdout
        .drain(0..7)
        .map(|x| x as char)
        .collect::<String>()
        .parse::<f64>()
        .unwrap();
    if res > 0.35 {
        assert!(
            false,
            "Too high similarity, mistake. Stdout:{:?}\nDigit: {}\n",
            output.stdout.as_slice(),
            res
        );
    }

    let paths = [
        "tests/casr_tests/casrep/test1/1.casrep",
        "tests/casr_tests/casrep/test1/2.casrep",
    ];
    let mut output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-cluster"))
        .args(&["-s", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(output.status.success());

    let res: f64 = output
        .stdout
        .drain(0..7)
        .map(|x| x as char)
        .collect::<String>()
        .parse::<f64>()
        .unwrap();
    if res < 0.70 {
        assert!(
            false,
            "Too small similarity, mistake. Stdout:{:?}\nDigit: {}\n",
            output.stdout.as_slice(),
            res
        );
    }
}

#[test]
fn test_casr_cluster_c() {
    let paths = [
        "tests/casr_tests/casrep/in",
        "tmp_tests_casr/clustering_out",
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-cluster"))
        .args(&["-c", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(output.status.success());

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
}

#[test]
fn test_casr_cluster_c_huge_san() {
    let paths = [
        "tests/casr_tests/casrep/test_clustering_san",
        "tmp_tests_casr/clustering_huge_out_san",
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-cluster"))
        .args(&["-d", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(output.status.success());

    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-cluster"))
        .args(&["-j", "6", "-c", &paths[1], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(output.status.success());

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

    assert_eq!(clusters_cnt, 14, "Invalid number of clusters");
    assert_eq!(
        std::fs::read_dir(paths[1].to_owned() + "/cl10")
            .unwrap()
            .count(),
        2,
        "Invalid number of reports in cluster 10"
    );
    assert_eq!(
        std::fs::read_dir(paths[1].to_owned() + "/cl12")
            .unwrap()
            .count(),
        1,
        "Invalid number of reports in cluster 12"
    );
}

#[test]
fn test_casr_cluster_c_huge_gdb() {
    let paths = [
        "tests/casr_tests/casrep/test_clustering_gdb",
        "tmp_tests_casr/clustering_huge_out_gdb",
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-cluster"))
        .args(&["-d", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(output.status.success());

    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-cluster"))
        .args(&["-j", "6", "-c", &paths[1], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(output.status.success());

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

    assert_eq!(clusters_cnt, 13, "Invalid number of clusters");
    assert_eq!(
        std::fs::read_dir(paths[1].to_owned() + "/cl1")
            .unwrap()
            .count(),
        3,
        "Invalid number of reports in cluster 1"
    );
    assert_eq!(
        std::fs::read_dir(paths[1].to_owned() + "/cl12")
            .unwrap()
            .count(),
        2,
        "Invalid number of reports in cluster 12"
    );
}

#[test]
fn test_casr_cluster_d() {
    let paths = [
        "tests/casr_tests/casrep/dedup/in",
        "tmp_tests_casr/dedup_out",
    ];

    let _ = fs::remove_dir_all(&paths[1]);

    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-cluster"))
        .args(&["-d", &paths[0], &paths[1]])
        .output()
        .expect("failed to start casr-cluster");

    assert!(output.status.success());

    let dirvec = match fs::read_dir(&paths[1]) {
        Ok(vec) => vec,
        Err(why) => {
            assert!(false, "{:?}", why.kind());
            return;
        }
    };

    let counter = dirvec.count();
    if counter != 2 {
        assert!(false, "Bad deduplication, casreps: {}", counter);
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_casr_san() {
    // Double free test
    let paths = [
        "tests/casr_tests/test_asan_df",
        "tests/casr_tests/test_asan_df",
    ];
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-san"))
        .args(&["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(output.status.success());

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

        assert_eq!(4, stacktrace.len());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "double-free");
        assert_eq!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_asan_df.cpp:8:5")
                // We build a test on ubuntu18 and run it on ubuntu20.
                // Debug information is broken.
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_asan_df+0x"),
            // We can't hardcode the offset because we rebuild tests every time.
            true
        );
    } else {
        assert!(false, "Couldn't parse json report file.");
    }

    // Stack-buffer-overflow test
    let paths = [
        "tests/casr_tests/test_asan_sbo",
        "tests/casr_tests/test_asan_sbo",
    ];
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-san"))
        .args(&["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(output.status.success());

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

        assert_eq!(3, stacktrace.len());
        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "stack-buffer-overflow(write)");
        assert_eq!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("test_asan_sbo.cpp:9:14")
                // We build a test on ubuntu18 and run it on ubuntu20.
                // Debug information is broken.
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_asan_sbo+0x"),
            // We can't hardcode the offset because we rebuild tests every time.
            true
        );
    } else {
        assert!(false, "Couldn't parse json report file.");
    }

    // Memory leaks test
    let paths = [
        "tests/casr_tests/test_asan_leak",
        "tests/casr_tests/test_asan_leak",
    ];
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-san"))
        .args(&["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(output.status.success());

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

        assert_eq!(3, stacktrace.len());
        assert_eq!(severity_type, "NOT_EXPLOITABLE");
        assert_eq!(severity_desc, "memory-leaks");
        assert_eq!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("leak.cpp:8:9")
                // We build a test on ubuntu18 and run it on ubuntu20.
                // Debug information is broken.
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_asan_leak+0x"),
            // We can't hardcode the offset because we rebuild tests every time.
            true
        );
    } else {
        assert!(false, "Couldn't parse json report file.");
    }

    // Test casr-san stdin
    let paths = [
        "tests/casr_tests/test_asan_stdin",
        "tests/casr_tests/test_asan_stdin",
    ];
    let mut tempfile = fs::File::create("/tmp/CasrSanTemp").unwrap();
    tempfile.write_all(b"2").unwrap();
    let output = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-san"))
        .args(&["--stdout", "--stdin", "/tmp/CasrSanTemp", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(output.status.success());
    fs::remove_file("/tmp/CasrSanTemp").unwrap();

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

        assert_eq!(3, stacktrace.len());
        assert_eq!(severity_type, "EXPLOITABLE");
        assert_eq!(severity_desc, "heap-buffer-overflow(write)");
        assert_eq!(
            report["CrashLine"]
                .as_str()
                .unwrap()
                .contains("stdin.cpp:20:14")
                // We build a test on ubuntu18 and run it on ubuntu20.
                // Debug information is broken.
                || report["CrashLine"]
                    .as_str()
                    .unwrap()
                    .contains("test_asan_stdin+0x"),
            // We can't hardcode the offset because we rebuild tests every time.
            true
        );
    } else {
        assert!(false, "Couldn't parse json report file.");
    }

    // Test casr-san ASLR
    let paths = [
        "tests/casr_tests/test_asan_sbo",
        "tests/casr_tests/test_asan_sbo",
    ];
    let output1 = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-san"))
        .args(&["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");
    let output2 = Command::new((*EXE_DIR.read().unwrap()).clone().join("casr-san"))
        .args(&["--stdout", "--", &paths[1]])
        .output()
        .expect("failed to start casr-san");

    assert!(output1.status.success());
    assert!(output2.status.success());

    let re = Regex::new(
        r"==[0-9]+==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x([0-9a-f]+)",
    )
    .unwrap();

    let report1: Result<Value, _> = serde_json::from_slice(&output1.stdout);
    let report2: Result<Value, _> = serde_json::from_slice(&output2.stdout);
    if let Ok(rep1) = report1 {
        if let Ok(rep2) = report2 {
            let asan1 = rep1["AsanReport"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.to_string())
                .nth(0)
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
                .nth(0)
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
                "Addresses must be equal! {} != {}",
                first_addr, second_addr
            );
            return;
        }
    }
    assert!(false, "Couldn't parse json report file.");
}

#[test]
fn test_asan_stacktrace() {
    let raw_stacktrace = &[ "#10 0x55ebfbfa0707 (/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz+0xfe2707) (BuildId: d2918819a864502448a61485c4b20818b0778ac2)",
        "#6 0x55ebfc1cabbc in rz_bin_open_buf (/home/user/Desk top/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz+0x120cbbc)",
        "#10 0x55ebfbfa0707 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz+0xfe2707)",
        "#9 0x43b1a1 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15",
        "#7 0x52433e in cmsIT8LoadFromMem /lcms/src/cmscgats.c:2438:10",
        "#7 0x52433e in cmsIT8LoadFromMem /lcms/src/cmscgats.c:2438",
        "#7 0x52433e in cmsIT8LoadFromMem /lcms/src/cmscgats.c",
        "#9 0x43b1a1 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp",
        "#4 0x998b40 in (anonymous namespace)::decrypt_xlsx(std::vector<unsigned char, std::allocator<unsigned char> > const&, std::__cxx11::basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t> > const&) /xlnt/source/detail/cryptography/xlsx_crypto_consumer.cpp:320:37",
        "#0 0x7f0a52c0fc59  /build/glibc-SzIz7B/glibc-2.31/string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:345",
        "#2 0x55ebfc21e12d in classes bin_dyldcache.c",
        "#2 0x55ebfc21e12d in classes+0x123 bin_dyldcache.c",
        "#2 0x55ebfc21e12d in classes+0x123 bin dyldcache.c",
        "#2 0x55ebfc21e12d bin_dyldcache.c",
        "#2 0x55ebfc21e12d bin dyldcache.c",
        "#9 0x43b1a1 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm -project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp",
        "#10 0x55ebfbfa0707 (/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz+0xfe2707) (BuildId: d2918819a864502448a61485c4b20818b0778ac2)",
        "#11 0xe086ff in xml::serializer::handle_error(genxStatus) const /xlnt/third-party/libstudxml/libstudxml/serializer.cxx:116:7",
    ];

    let trace = raw_stacktrace
        .into_iter()
        .map(|e| e.to_string())
        .collect::<Vec<String>>();
    let sttr = casr::asan::stacktrace_from_asan(&trace);
    if sttr.is_err() {
        assert!(false, "{}", sttr.err().unwrap());
    }

    let stacktrace = sttr.unwrap();
    assert_eq!(stacktrace[0].address, 0x55ebfbfa0707);
    assert_eq!(stacktrace[0].offset, 0xfe2707);
    assert_eq!(
        stacktrace[0].module,
        "/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz".to_string()
    );

    assert_eq!(stacktrace[1].address, 0x55ebfc1cabbc);
    assert_eq!(stacktrace[1].offset, 0x120cbbc);
    assert_eq!(
        stacktrace[1].module,
        "/home/user/Desk top/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz".to_string()
    );
    assert_eq!(stacktrace[1].function, "rz_bin_open_buf".to_string());

    assert_eq!(stacktrace[2].address, 0x55ebfbfa0707);
    assert_eq!(stacktrace[2].offset, 0xfe2707);
    assert_eq!(
        stacktrace[2].module,
        "/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz".to_string()
    );
    assert_eq!(
        stacktrace[2].function,
        "fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long))"
            .to_string()
    );

    assert_eq!(stacktrace[3].address, 0x43b1a1);
    assert_eq!(
        stacktrace[3].function,
        "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)".to_string()
    );
    assert_eq!(
        stacktrace[3].debug.file,
        "/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp".to_string()
    );
    assert_eq!(stacktrace[3].debug.line, 611);
    assert_eq!(stacktrace[3].debug.column, 15);

    assert_eq!(stacktrace[4].address, 0x52433e);
    assert_eq!(stacktrace[4].function, "cmsIT8LoadFromMem".to_string());
    assert_eq!(stacktrace[4].debug.file, "/lcms/src/cmscgats.c".to_string());
    assert_eq!(stacktrace[4].debug.line, 2438);
    assert_eq!(stacktrace[4].debug.column, 10);

    assert_eq!(stacktrace[5].address, 0x52433e);
    assert_eq!(stacktrace[5].function, "cmsIT8LoadFromMem".to_string());
    assert_eq!(stacktrace[5].debug.file, "/lcms/src/cmscgats.c".to_string());
    assert_eq!(stacktrace[5].debug.line, 2438);

    assert_eq!(stacktrace[6].address, 0x52433e);
    assert_eq!(stacktrace[6].function, "cmsIT8LoadFromMem".to_string());
    assert_eq!(stacktrace[6].debug.file, "/lcms/src/cmscgats.c".to_string());

    assert_eq!(stacktrace[7].address, 0x43b1a1);
    assert_eq!(
        stacktrace[7].function,
        "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)".to_string()
    );
    assert_eq!(
        stacktrace[7].debug.file,
        "/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp".to_string()
    );

    assert_eq!(stacktrace[8].address, 0x998b40);
    assert_eq!(stacktrace[8].function, "(anonymous namespace)::decrypt_xlsx(std::vector<unsigned char, std::allocator<unsigned char> > const&, std::__cxx11::basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t> > const&)".to_string());
    assert_eq!(
        stacktrace[8].debug.file,
        "/xlnt/source/detail/cryptography/xlsx_crypto_consumer.cpp".to_string()
    );
    assert_eq!(stacktrace[8].debug.line, 320);
    assert_eq!(stacktrace[8].debug.column, 37);

    assert_eq!(stacktrace[9].address, 0x7f0a52c0fc59);
    assert_eq!(
        stacktrace[9].debug.file,
        "/build/glibc-SzIz7B/glibc-2.31/string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S".to_string()
    );
    assert_eq!(stacktrace[9].debug.line, 345);

    assert_eq!(stacktrace[10].address, 0x55ebfc21e12d);
    assert_eq!(stacktrace[10].function, "classes");
    assert_eq!(stacktrace[10].debug.file, "bin_dyldcache.c");

    assert_eq!(stacktrace[11].address, 0x55ebfc21e12d);
    assert_eq!(stacktrace[11].function, "classes+0x123");
    assert_eq!(stacktrace[11].debug.file, "bin_dyldcache.c");

    assert_eq!(stacktrace[12].address, 0x55ebfc21e12d);
    assert_eq!(stacktrace[12].function, "classes+0x123");
    assert_eq!(stacktrace[12].debug.file, "bin dyldcache.c");

    assert_eq!(stacktrace[13].address, 0x55ebfc21e12d);
    assert_eq!(stacktrace[13].debug.file, "bin_dyldcache.c");

    assert_eq!(stacktrace[14].address, 0x55ebfc21e12d);
    assert_eq!(stacktrace[14].debug.file, "bin dyldcache.c");

    assert_eq!(stacktrace[15].address, 0x43b1a1);
    assert_eq!(
        stacktrace[15].function,
        "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)".to_string()
    );
    assert_eq!(
        stacktrace[15].debug.file,
        "/llvm -project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp".to_string()
    );

    assert_eq!(stacktrace[16].address, 0x55ebfbfa0707);
    assert_eq!(stacktrace[16].offset, 0xfe2707);
    assert_eq!(
        stacktrace[16].module,
        "/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz".to_string()
    );

    assert_eq!(stacktrace[17].address, 0xe086ff);
    assert_eq!(
        stacktrace[17].function,
        "xml::serializer::handle_error(genxStatus) const".to_string()
    );
    assert_eq!(
        stacktrace[17].debug.file,
        "/xlnt/third-party/libstudxml/libstudxml/serializer.cxx".to_string()
    );
    assert_eq!(stacktrace[17].debug.line, 116);
    assert_eq!(stacktrace[17].debug.column, 7);
}
