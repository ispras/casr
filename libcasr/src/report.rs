//! Report contains the main struct `CrashReport` with all information about crash.
use crate::asan::AsanStacktrace;
use crate::error;
use crate::error::*;
use crate::execution_class::*;
use crate::gdb::GdbStacktrace;
use crate::go::GoStacktrace;
use crate::java::JavaStacktrace;
use crate::python::PythonStacktrace;
use crate::rust::RustStacktrace;
use crate::stacktrace::*;
use chrono::prelude::*;
use gdb_command::mappings::{MappedFiles, MappedFilesExt};
use gdb_command::registers::Registers;
use gdb_command::stacktrace::StacktraceExt;
use regex::Regex;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::Command;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents the information about program termination.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Clone, Debug)]
pub struct CrashReport {
    /// Pid of crashed process.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub pid: i32,
    /// Date and time of the problem report in ISO format. (see asctime(3)).
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "Date", deserialize = "Date"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub date: String,
    /// Output of uname -a.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "Uname", deserialize = "Uname"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub uname: String,
    /// Name of the operating system. On LSB compliant systems, this can be determined with lsb_release -si.
    #[cfg_attr(feature = "serde", serde(rename(serialize = "OS", deserialize = "OS")))]
    #[cfg_attr(feature = "serde", serde(default))]
    pub os: String,
    /// Release version of the operating system. On LSB compliant systems, this can be determined with lsb_release -sr.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "OSRelease", deserialize = "OSRelease"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub os_release: String,
    /// OS specific notation of processor/system architecture (e. g. i386).
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "Architecture", deserialize = "Architecture"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub architecture: String,
    /// Contents of /proc/pid/exe for ELF files; if the process is an interpreted script, this is the script path instead.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "ExecutablePath", deserialize = "ExecutablePath"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub executable_path: String,
    /// Subset of the process’ environment, from /proc/pid/env; this should only show some standard variables that.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "ProcEnviron", deserialize = "ProcEnviron"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub proc_environ: Vec<String>,
    /// Contents of /proc/pid/cmdline.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "ProcCmdline", deserialize = "ProcCmdline"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub proc_cmdline: String,
    /// Path to stdin for target
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "Stdin", deserialize = "Stdin"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub stdin: String,
    /// Contents of /proc/pid/status.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "ProcStatus", deserialize = "ProcStatus"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub proc_status: Vec<String>,
    /// Contents of /proc/pid/maps.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "ProcMaps", deserialize = "ProcMaps"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub proc_maps: Vec<String>,
    /// Opend files at crash : ls -lah /proc/\<pid\>/fd.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "ProcFiles", deserialize = "ProcFiles"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub proc_fd: Vec<String>,
    /// Opened network connections.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "NetworkConnections", deserialize = "NetworkConnections"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub network_connections: Vec<String>,
    /// Crash classification.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "CrashSeverity", deserialize = "CrashSeverity"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub execution_class: ExecutionClass,
    /// Stack trace for crashed thread.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "Stacktrace", deserialize = "Stacktrace"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub stacktrace: Vec<String>,
    /// Registers state for crashed thread.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "Registers", deserialize = "Registers"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub registers: Registers,
    /// Disassembly for crashed state (16 instructions).
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "Disassembly", deserialize = "Disassembly"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub disassembly: Vec<String>,
    /// Package name.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "Package", deserialize = "Package"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub package: String,
    /// Package version.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "PackageVersion", deserialize = "PackageVersion"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub package_version: String,
    /// Package architecture.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "PackageArchitecture", deserialize = "PackageArchitecture"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub package_architecture: String,
    /// Package description.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "PackageDescription", deserialize = "PackageDescription"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub package_description: String,
    /// Asan report.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "AsanReport", deserialize = "AsanReport"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub asan_report: Vec<String>,
    /// Ubsan report.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "UbsanReport", deserialize = "UbsanReport"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub ubsan_report: Vec<String>,
    /// Python report.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "PythonReport", deserialize = "PythonReport"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub python_report: Vec<String>,
    /// Go report.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "GoReport", deserialize = "GoReport"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub go_report: Vec<String>,
    /// Java report.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "JavaReport", deserialize = "JavaReport"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub java_report: Vec<String>,
    /// Rust report.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "RustReport", deserialize = "RustReport"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub rust_report: Vec<String>,
    /// Crash line from stack trace: source:line or binary+offset.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "CrashLine", deserialize = "CrashLine"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub crashline: String,
    /// Source code fragment.
    #[cfg_attr(
        feature = "serde",
        serde(rename(serialize = "Source", deserialize = "Source"))
    )]
    #[cfg_attr(feature = "serde", serde(default))]
    pub source: Vec<String>,
}

impl CrashReport {
    /// Create new `CrashReport`
    pub fn new() -> Self {
        let mut report: CrashReport = Default::default();
        let local: DateTime<Local> = Local::now();
        report.date = local.to_rfc3339_opts(SecondsFormat::Micros, false);
        report
    }

    /// Add information about opened network connections
    pub fn add_network_connections(&mut self) -> error::Result<()> {
        let mut ss_cmd = Command::new("ss");
        ss_cmd.arg("-tuap");
        let ss_out = ss_cmd.output()?;
        if ss_out.status.success() {
            if let Ok(network_info) = String::from_utf8(ss_out.stdout) {
                self.network_connections = network_info
                    .split_terminator('\n')
                    .map(|s| s.to_string())
                    .filter(|s| s.contains(&format!("pid={}", self.pid)))
                    .collect();
            }
        }

        Ok(())
    }

    /// Add information about operation system
    pub fn add_os_info(&mut self) -> error::Result<()> {
        // Get os and os release.
        let mut info_cmd = Command::new("sh");
        info_cmd.arg("-c").arg("lsb_release -sir");
        let info_out = info_cmd.output()?;
        if info_out.status.success() {
            if let Ok(info) = String::from_utf8(info_out.stdout) {
                info.split('\n').enumerate().for_each(|(i, s)| match i {
                    0 => {
                        self.os = s.trim().to_string();
                    }
                    1 => {
                        self.os_release = s.trim().to_string();
                    }
                    _ => {}
                });
            }
        }
        // Get uname -a.
        let mut uname_cmd = Command::new("sh");
        uname_cmd.arg("-c").arg("uname -a");
        let uname_out = uname_cmd.output()?;
        if uname_out.status.success() {
            if let Ok(uname) = String::from_utf8(uname_out.stdout) {
                self.uname = uname.trim().to_string();
            }
        }
        // Get Architecture for Debian based only. TODO: rpm.
        let mut dpkg_cmd = Command::new("sh");
        dpkg_cmd.arg("-c").arg("dpkg --print-architecture");
        let dpkg_out = dpkg_cmd.output()?;
        if dpkg_out.status.success() {
            if let Ok(dpkg) = String::from_utf8(dpkg_out.stdout) {
                self.architecture = dpkg.trim().to_string();
            }
        }

        Ok(())
    }

    /// Anonymize environment variables.
    fn anonymize_env(&mut self) {
        // TODO: Add more.
        let sensitive = Regex::new(concat!(
            "^CI=|^HOSTNAME=|^LOGNAME=|^USERNAME=|^LANG=|^SESSION_MANAGER=|",
            "^XAUTHORITY=|^CI_|^GITLAB_|^FF_|^LC_|^SSH_|^XDG_|^GTK_|^GIO_|",
            "^DESKTOP_|^DBUS_|^GNOME_|^TERMINATOR_|^GPG_|^LS_COLORS=|",
            "^LESSCLOSE=|^LESSOPEN=",
        ))
        .unwrap();
        self.proc_environ.retain(|e| !sensitive.is_match(e));
    }

    /// Add information about running process
    pub fn add_proc_info(&mut self) -> error::Result<()> {
        // Get executable path.
        let mut path = PathBuf::new();
        path.push("/proc");
        path.push(self.pid.to_string());
        // Check if process is still alive.
        if !path.exists() {
            return Err(error::Error::Casr(format!(
                "No process with pid {} exists",
                self.pid
            )));
        }
        // Set opend files.
        path.push("fd");
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let path = entry.path();
            if let Ok(file) = fs::read_link(path) {
                if !file.starts_with("/dev/pts/") {
                    let f = file.to_str().unwrap().to_string();
                    if !f.contains("socket:") {
                        self.proc_fd.push(f);
                    }
                }
            }
        }
        path.pop();
        path.push("exe");
        if let Ok(exe) = fs::read_link(&path) {
            self.executable_path = exe.to_str().unwrap().to_string();
        }
        path.pop();
        // Get cmd line.
        path.push("cmdline");
        let mut file = File::open(&path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        buffer = buffer
            .iter()
            .map(|e| if *e == 0 { 0x20 } else { *e })
            .collect();
        self.proc_cmdline = String::from_utf8(buffer)
            .unwrap_or_default()
            .trim()
            .to_string();
        path.pop();
        let mut s = String::new();

        // Get maps. Save them in GDB format.
        path.push("maps");
        let mut file = File::open(path.clone())?;
        file.read_to_string(&mut s)?;
        s.split_terminator('\n')
            .map(|x| {
                let x = x.replacen('-', " ", 1);
                x.split(' ')
                    .map(|x| x.trim().to_string())
                    .collect::<Vec<String>>()
            })
            .for_each(|x| {
                self.proc_maps.push(format!(
                    "0x{:<15} 0x{:<15} 0x{:<10x} 0x{:<10} {}",
                    x[0],
                    x[1],
                    u64::from_str_radix(x[1].as_str(), 16).unwrap()
                        - u64::from_str_radix(x[0].as_str(), 16).unwrap(),
                    x[3],
                    x[x.len() - 1]
                ))
            });
        path.pop();

        // Get status.
        path.push("status");
        s = String::new();
        let mut file = File::open(path.clone())?;
        file.read_to_string(&mut s)?;
        self.proc_status = s.split_terminator('\n').map(|s| s.to_string()).collect();

        // Get environ.
        path.pop();
        path.push("environ");
        let mut file = File::open(path.clone())?;
        buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        buffer = buffer
            .iter()
            .map(|e| if *e == 0 { b'\n' } else { *e })
            .collect();
        s = String::from_utf8(buffer)
            .unwrap_or_default()
            .trim()
            .to_string();
        self.proc_environ = s.split_terminator('\n').map(|s| s.to_string()).collect();
        self.anonymize_env();
        Ok(())
    }

    /// Add current process environment variables
    pub fn add_proc_environ(&mut self) -> error::Result<()> {
        self.proc_environ = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
        self.anonymize_env();
        Ok(())
    }

    /// Add package information.
    pub fn add_package_info(&mut self) -> error::Result<()> {
        if self.executable_path.is_empty() {
            return Err(error::Error::Casr(
                "Coudn't find package. No executable in report".to_string(),
            ));
        }
        let path = PathBuf::from(&self.executable_path);
        let possible_paths = [
            "/bin/", "/boot", "/etc/", "/initrd", "/lib", "/sbin/", "/opt", "/usr/", "/var",
        ];
        // Check if binary likely packaged.
        if possible_paths.iter().any(|e| path.starts_with(e)) {
            // TODO: Support not only Debian-based packet managers
            let mut dpkg_cmd = Command::new("sh");
            dpkg_cmd
                .arg("-c")
                .arg(format!("dpkg -S {}", &path.to_str().unwrap()));
            let dpkg_out = dpkg_cmd.output()?;
            if dpkg_out.status.success() {
                if let Ok(mut package) = String::from_utf8(dpkg_out.stdout) {
                    if let Some(index) = package.find(':') {
                        package.truncate(index);
                        self.package = package;

                        // Extra info about package.
                        let mut dpkgl_cmd = Command::new("sh");
                        dpkgl_cmd.arg("-c").arg(format!("dpkg -l {}", self.package));
                        let dpkgl_out = dpkgl_cmd.output()?;
                        if dpkgl_out.status.success() {
                            if let Ok(info) = String::from_utf8(dpkgl_out.stdout) {
                                if let Some((_, info)) = info.rsplit_once('\n') {
                                    info.split_whitespace().enumerate().for_each(
                                        |(i, e)| match i {
                                            0 | 1 => {}
                                            2 => {
                                                self.package_version = e.to_string();
                                            }
                                            3 => {
                                                self.package_architecture = e.to_string();
                                            }
                                            _ => {
                                                self.package_description.push_str(e);
                                                self.package_description.push(' ');
                                            }
                                        },
                                    );
                                    self.package_description =
                                        self.package_description.trim().to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Get source code fragment for crash line
    ///
    /// # Arguments
    ///
    /// * 'debug' - debug information
    pub fn sources(debug: &DebugInfo) -> Option<Vec<String>> {
        if debug.line == 0 {
            return None;
        }

        if let Ok(file) = std::fs::File::open(&debug.file) {
            let file = BufReader::new(file);
            let start: usize = if debug.line > 5 {
                debug.line as usize - 5
            } else {
                0
            };
            let mut lines: Vec<String> = file
                .lines()
                .skip(start)
                .enumerate()
                .take_while(|(i, _)| *i < 10)
                .map(|(i, l)| {
                    if let Ok(l) = l {
                        format!("    {:<6} {}", start + i + 1, l.trim_end())
                    } else {
                        format!("    {:<6} Corrupted line", start + i + 1)
                    }
                })
                .collect::<Vec<String>>();
            let crash_line = debug.line as usize - start - 1;
            if crash_line < lines.len() {
                lines[crash_line].replace_range(..4, "--->");
                return Some(lines);
            }
        }

        None
    }

    /// Add disassembly as strings
    ///
    /// # Arguments
    ///
    /// * `gdb_asm` - disassembly from gdb
    pub fn set_disassembly(&mut self, gdb_asm: &str) {
        // Remove module names from disassembly for pretty view in report.
        let rm_modules = Regex::new("<.*?>").unwrap();
        let disassembly = rm_modules.replace_all(gdb_asm, "");

        self.disassembly = disassembly.split('\n').map(|x| x.to_string()).collect();
    }

    /// Filter frames from the stack trace that are not related to analyzed code containing crash
    /// and return it as `Stacktrace` struct
    pub fn filtered_stacktrace(&self) -> Result<Stacktrace> {
        let mut rawtrace = if !self.asan_report.is_empty() {
            AsanStacktrace::parse_stacktrace(&self.stacktrace)?
        } else if !self.python_report.is_empty() {
            PythonStacktrace::parse_stacktrace(&self.stacktrace)?
        } else if !self.java_report.is_empty() {
            JavaStacktrace::parse_stacktrace(&self.stacktrace)?
        } else if !self.go_report.is_empty() {
            GoStacktrace::parse_stacktrace(&self.stacktrace)?
        } else if !self.rust_report.is_empty() {
            RustStacktrace::parse_stacktrace(&self.stacktrace)?
        } else {
            GdbStacktrace::parse_stacktrace(&self.stacktrace)?
        };

        // Get Proc mappings from Casr report
        if !self.proc_maps.is_empty() {
            let mappings = MappedFiles::from_gdb(self.proc_maps.join("\n"))?;
            rawtrace.compute_module_offsets(&mappings);
        }

        rawtrace.filter();

        if rawtrace.is_empty() {
            return Err(Error::Casr(
                "Current stack trace length is null".to_string(),
            ));
        }

        Ok(rawtrace)
    }
}

impl fmt::Display for CrashReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut report = String::new();
        // CrashLine
        if !self.crashline.is_empty() {
            report += &format!("CrashLine: {}\n\n", &self.crashline);
        }

        // Date
        if !self.date.is_empty() {
            report += &format!("Date: {}\n", &self.date);
        }

        // Uname
        if !self.uname.is_empty() {
            report += &format!("Uname: {}\n", &self.uname);
        }

        // OS
        if !self.os.is_empty() {
            report += &format!("OS: {}\n", &self.os);
        }

        // OSRelease
        if !self.os_release.is_empty() {
            report += &format!("OSRelease: {}\n", &self.os_release);
        }

        // Architecture
        if !self.architecture.is_empty() {
            report += &format!("Architecture: {}\n", &self.architecture);
        }

        // ExecutablePath
        if !self.executable_path.is_empty() {
            report += &format!("ExecutablePath: {}\n", &self.executable_path);
        }

        // ProcEnviron
        if !self.proc_environ.is_empty() {
            report += "\n===ProcEnviron===\n";
            report += &(self.proc_environ.join("\n") + "\n");
        }

        // ProcCmdline
        if !self.proc_cmdline.is_empty() {
            report += &format!("\nProcCmdline: {}\n", &self.proc_cmdline);
        }

        // Stdin
        if !self.stdin.is_empty() {
            report += &format!("\nStdin: {}\n", &self.stdin);
        }

        // ProcStatus
        if !self.proc_status.is_empty() {
            report += "\n===ProcStatus===\n";
            report += &(self.proc_status.join("\n") + "\n");
        }

        // ProcFiles
        if !self.proc_maps.is_empty() {
            report += "\n===ProcFiles===\n";
            report += &(self.proc_maps.join("\n") + "\n");
        }

        // NetworkConnections
        if !self.proc_fd.is_empty() {
            report += "\n===NetworkConnections===\n";
            report += &(self.proc_fd.join("\n") + "\n");
        }

        report += &format!("\n===CrashSeverity===\n{}\n", self.execution_class);

        // Stacktrace
        if !self.stacktrace.is_empty() {
            report += "\n===Stacktrace===\n";
            report += &(self.stacktrace.join("\n") + "\n");
        }

        // Registers
        if !self.registers.is_empty() {
            report += "\n===CrashState===\n";
            for (reg, value) in &self.registers {
                report += &format!("{reg}:    0x{value:x}\n");
            }

            report += "\n";

            // Disassembly
            if !self.disassembly.is_empty() {
                report += &(self.disassembly.join("\n") + "\n");
            }
        }

        // Package
        if !self.package.is_empty() {
            report += &format!("\nPackage: {}\n", &self.package);
        }

        // PackageVersion
        if !self.package_version.is_empty() {
            report += &format!("PackageVersion: {}\n", &self.package_version);
        }

        // PackageArchitecture
        if !self.package_architecture.is_empty() {
            report += &format!("PackageArchitecture: {}\n", &self.package_architecture);
        }

        // PackageDescription
        if !self.package_description.is_empty() {
            report += &format!("PackageDescription: {}\n", &self.package_description);
        }

        // ASANreport
        if !self.asan_report.is_empty() {
            report += "\n===AsanReport===\n";
            report += &(self.asan_report.join("\n") + "\n");
        }

        // UBSANreport
        if !self.ubsan_report.is_empty() {
            report += "\n===UbsanReport===\n";
            report += &(self.ubsan_report.join("\n") + "\n");
        }

        // PythonReport
        if !self.python_report.is_empty() {
            report += "\n===PythonReport===\n";
            for e in self.python_report.iter() {
                report += &format!("{e}\n");
            }
        }

        // JavaReport
        if !self.java_report.is_empty() {
            report += "\n===JavaReport===\n";
            for e in self.java_report.iter() {
                report += &format!("{e}\n");
            }
        }

        // GoReport
        if !self.go_report.is_empty() {
            report += "\n===GoReport===\n";
            for e in self.go_report.iter() {
                report += &format!("{e}\n");
            }
        }

        // RustReport
        if !self.rust_report.is_empty() {
            report += "\n===RustReport===\n";
            for e in self.rust_report.iter() {
                report += &format!("{e}\n");
            }
        }

        // Source
        if !self.source.is_empty() {
            report += "\n===Source===\n";
            report += &(self.source.join("\n") + "\n");
        }

        write!(f, "{}", report.trim())
    }
}

/// Deduplicate `CrashReport`'s
///
/// # Arguments
///
/// * `casreps` - slice of `CrashReport`
///
/// # Return value
///
/// An vector of the same length as `[CrashReport]`.
/// Vec\[i\] is false, if original CrashReport i is a duplicate of any element of `[CrashReport]`.
pub fn dedup_reports(casreps: &[CrashReport]) -> Result<Vec<bool>> {
    let traces: Vec<Stacktrace> = casreps
        .iter()
        .map(|report| report.filtered_stacktrace())
        .collect::<Result<_>>()?;

    Ok(dedup_stacktraces(&traces))
}

/// Perform the clustering of `CrashReport`'s
///
/// # Arguments
///
/// * `casreps` - slice of `CrashReport`
///
/// # Return value
///
/// An vector of the same length as `[CrashReport]`
/// Vec\[i\] is the flat cluster number to which original `CrashReport` i belongs.
pub fn cluster_reports(casreps: &[CrashReport]) -> Result<Vec<u32>> {
    let traces: Vec<Stacktrace> = casreps
        .iter()
        .map(|report| report.filtered_stacktrace())
        .collect::<Result<_>>()?;

    cluster_stacktraces(&traces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use crate::init_ignored_frames;

    #[test]
    fn test_report_display() {
        // TODO: Fill all empty fields
        let report = CrashReport {
            proc_fd: vec![],
            network_connections: vec![],
            registers: Registers::new(),
            package: "".to_string(),
            package_version: "".to_string(),
            package_architecture: "".to_string(),
            package_description: "".to_string(),
            crashline: "/gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/basic_string.h:187:28".to_string(),
            date: "2023-09-29T15:31:39.818262+03:00".to_string(),
            uname: "Linux astra-stand 5.15.0-84-generic #93-Ubuntu SMP Tue Sep 5 17:16:10 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux".to_string(),
            os: "Ubuntu".to_string(),
            os_release: "22.04".to_string(),
            architecture: "amd64".to_string(),
            executable_path: "/home/hkctkuy/github/casr/casr/tests/casr_tests/bin/load_fuzzer".to_string(),
            proc_environ: vec!["CARGO=/home/hkctkuy/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/cargo".to_string()],
            proc_cmdline: "/home/hkctkuy/github/casr/casr/tests/casr_tests/bin/load_fuzzer /home/hkctkuy/github/casr/casr/tests/casr_tests/casrep/libfuzzer_crashes_xlnt/crash-49c4e6270849ab5c9c13f64b98f817efa840d8a3".to_string(),
            stdin: "/home/hkctkuy/github/casr/casr/tests/casr_tests/casrep/afl-out-xlnt-small/afl_main-worker/crashes/id:000007,sig:00,sync:afl_s01-worker,src:000371".to_string(),
            proc_status: vec!["process 2945397".to_string()],
            proc_maps: vec![
                "      0x555555554000     0x555555556000     0x2000        0x0 /usr/local/bin/tiff2pdf".to_string(),
            ],
            stacktrace: vec![
                "    #0 0x4ca0e0 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>::_M_data() const /gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/basic_string.h:187:28".to_string(),
                "    #1 0x4ca0e0 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>::_M_is_local() const /gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/basic_string.h:222:26".to_string(),
                "    #2 0x455d32 in main /llvm-project-llvmorg-14.0.0/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10".to_string(),
                "    #3 0x7ffff7c8bd8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16".to_string(),
                "    #4 0x7ffff7c8be3f in __libc_start_main csu/../csu/libc-start.c:392:3".to_string(),
                "    #5 0x421ad8 in _start (/home/hkctkuy/github/casr/casr/tests/casr_tests/bin/load_fuzzer+0x421ad8)".to_string(),
            ],
            disassembly: vec!["==> 0x5e425d: mov eax, dword ptr [rax]".to_string()],
            asan_report: vec![
                "==363912==ERROR: AddressSanitizer: SEGV on unknown address 0xffffffffffffffe0 (pc 0x0000004ca0e0 bp 0x7fffffff9980 sp 0x7fffffff9928 T0)".to_string(),
                "==363912==The signal is caused by a READ memory access.".to_string(),
                "    #0 0x4ca0e0 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>::_M_data() const /gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/basic_string.h:187:28".to_string(),
                "    #1 0x4ca0e0 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>::_M_is_local() const /gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/basic_string.h:222:26".to_string(),
                "    #2 0x455d32 in main /llvm-project-llvmorg-14.0.0/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10".to_string(),
                "    #3 0x7ffff7c8bd8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16".to_string(),
                "    #4 0x7ffff7c8be3f in __libc_start_main csu/../csu/libc-start.c:392:3".to_string(),
                "    #5 0x421ad8 in _start (/home/hkctkuy/github/casr/casr/tests/casr_tests/bin/load_fuzzer+0x421ad8)".to_string(),
                "".to_string(),
                "AddressSanitizer can not provide additional info.".to_string(),
                "SUMMARY: AddressSanitizer: SEGV /gcc-build/x86_64-pc-linux-gnu/libstdc++-v3/include/bits/basic_string.h:187:28 in std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>::_M_data() const".to_string(),
                "==363912==ABORTING".to_string(),
            ],
            ubsan_report: vec![
                "/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/test_casr_ubsan/test_ubsan.cpp:4:29: runtime error: signed integer overflow: 65535 * 32769 cannot be represented in type 'int'".to_string(),
                "    #0 0x55a13df62356 in main /home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/test_casr_ubsan/test_ubsan.cpp:4:29".to_string(),
                "    #1 0x7fcb17fd1d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16".to_string(),
                "    #2 0x7fcb17fd1e3f in __libc_start_main csu/../csu/libc-start.c:392:3".to_string(),
                "    #3 0x55a13df38394 in _start (/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/test_casr_ubsan/test_ubsan+0x5394) (BuildId: 0aa8e083e8d61ffb756f6009a87413247b0d8ba9)".to_string(),
                "".to_string(),
                "SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow /home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/test_casr_ubsan/test_ubsan.cpp:4:29 in".to_string(),
            ],
            python_report: vec![
                " === Uncaught Python exception: ===".to_string(),
                "TypeError: unhashable type: 'list'".to_string(),
                "Traceback (most recent call last):".to_string(),
                "  File \"/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/yaml_fuzzer.py\".to_string(), line 38, in TestOneInput".to_string(),
                "    try:".to_string(),
                "  File \"/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/ruamel/yaml/main.py\".to_string(), line 461, in load_all".to_string(),
                "    yield constructor.get_data()".to_string(),
                "  File \"/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/ruamel/yaml/constructor.py\".to_string(), line 111, in get_data".to_string(),
                "    # type: () -> Any".to_string(),
                "  File \"/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/ruamel/yaml/constructor.py\".to_string(), line 129, in construct_document".to_string(),
                "    self.state_generators = []".to_string(),
                "  File \"/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/ruamel/yaml/constructor.py\".to_string(), line 674, in construct_yaml_map".to_string(),
                "    value = self.construct_mapping(node)".to_string(),
                "  File \"/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/ruamel/yaml/constructor.py\".to_string(), line 440, in construct_mapping".to_string(),
                "    \"\"\"deep is True when creating an object/mapping recursively,".to_string(),
                "  File \"/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/ruamel/yaml/constructor.py\".to_string(), line 258, in construct_mapping".to_string(),
                "    key_node.start_mark,".to_string(),
                "  File \"/home/hkctkuy/github/casr/casr/tests/tmp_tests_casr/ruamel/yaml/constructor.py\".to_string(), line 270, in check_mapping_key".to_string(),
                "    def check_mapping_key(self, node, key_node, mapping, key, value):".to_string(),
                "TypeError: unhashable type: 'list'".to_string(),
            ],
            java_report: vec![
                "== Java Exception: java.lang.IndexOutOfBoundsException: start 59, end 22, length 60".to_string(),
                "\tat java.base/java.lang.AbstractStringBuilder.checkRange(AbstractStringBuilder.java:1802)".to_string(),
                "\tat java.base/java.lang.AbstractStringBuilder.append(AbstractStringBuilder.java:680)".to_string(),
                "\tat java.base/java.lang.StringBuilder.append(StringBuilder.java:218)".to_string(),
                "\tat com.google.json.JsonSanitizer.elide(JsonSanitizer.java:717)".to_string(),
                "\tat com.google.json.JsonSanitizer.normalizeNumber(JsonSanitizer.java:864)".to_string(),
                "\tat com.google.json.JsonSanitizer.sanitize(JsonSanitizer.java:440)".to_string(),
                "\tat com.google.json.JsonSanitizer.sanitize(JsonSanitizer.java:122)".to_string(),
                "\tat DenylistFuzzer.fuzzerTestOneInput(DenylistFuzzer.java:27)".to_string(),
                "\tat com.code_intelligence.jazzer.driver.FuzzTargetRunner.runOne(FuzzTargetRunner.java:198)".to_string(),
                "\tat com.code_intelligence.jazzer.runtime.FuzzTargetRunnerNatives.startLibFuzzer(Native Method)".to_string(),
                "\tat com.code_intelligence.jazzer.driver.FuzzTargetRunner.startLibFuzzer(FuzzTargetRunner.java:504)".to_string(),
                "\tat com.code_intelligence.jazzer.driver.FuzzTargetRunner.startLibFuzzer(FuzzTargetRunner.java:381)".to_string(),
                "\tat com.code_intelligence.jazzer.driver.Driver.start(Driver.java:147)".to_string(),
                "\tat com.code_intelligence.jazzer.Jazzer.start(Jazzer.java:113)".to_string(),
                "\tat com.code_intelligence.jazzer.Jazzer.main(Jazzer.java:73)".to_string(),
            ],
            go_report: vec![
                "Flag: verbosity 2".to_string(),
                "Flag: dict /webp.dict".to_string(),
                "Flag: rss_limit_mb 8192".to_string(),
                "Flag: close_fd_mask 1".to_string(),
                "Dictionary: 44 entries".to_string(),
                "INFO: Running with entropic power schedule (0xFF, 100).".to_string(),
                "INFO: Seed: 2143190736".to_string(),
                "INFO: 65536 Extra Counters".to_string(),
                "/image/fuzz_webp: Running 1 inputs 1 time(s) each.".to_string(),
                "Running: /builds/dse/gitlab-jobs/oss-sydr-fuzz/projects/image-go/webp-out/crashes/crash-00ff2f41cc18f52217438b15b2d2d5037d217741".to_string(),
                "fatal error: runtime: out of memory".to_string(),
                "".to_string(),
                "runtime stack:".to_string(),
                "runtime.throw({0x565860?, 0x200000?})".to_string(),
                "\truntime/panic.go:1047 +0x5f fp=0x7fffffffbcc0 sp=0x7fffffffbc90 pc=0x49731f".to_string(),
                "runtime.sysMapOS(0xc000400000, 0x8bc97800000?)".to_string(),
                "\truntime/mem_linux.go:187 +0x11b fp=0x7fffffffbd08 sp=0x7fffffffbcc0 pc=0x47a7fb".to_string(),
                "runtime.sysMap(0xff9e40?, 0x7ffff7a14000?, 0x48dac0?)".to_string(),
                "\truntime/mem.go:142 +0x35 fp=0x7fffffffbd38 sp=0x7fffffffbd08 pc=0x47a1d5".to_string(),
                "runtime.(*mheap).grow(0xff9e40, 0x45e4bbda?)".to_string(),
                "\truntime/mheap.go:1459 +0x23d fp=0x7fffffffbda8 sp=0x7fffffffbd38 pc=0x48ab7d".to_string(),
                "runtime.(*mheap).allocSpan(0xff9e40, 0x45e4bbda, 0x0, 0x1)".to_string(),
                "\truntime/mheap.go:1191 +0x1be fp=0x7fffffffbe40 sp=0x7fffffffbda8 pc=0x48a2be".to_string(),
                "runtime.(*mheap).alloc.func1()".to_string(),
                "\truntime/mheap.go:910 +0x65 fp=0x7fffffffbe88 sp=0x7fffffffbe40 pc=0x489d45".to_string(),
                "runtime.systemstack()".to_string(),
                "\truntime/asm_amd64.s:492 +0x46 fp=0x7fffffffbe90 sp=0x7fffffffbe88 pc=0x4c09a6".to_string(),
                "".to_string(),
                "==32824== ERROR: libFuzzer: deadly signal".to_string(),
                "    #0 0x465074 in __sanitizer_print_stack_trace /llvm-project-llvmorg-14.0.6/compiler-rt/lib/ubsan/ubsan_diag_standalone.cpp:31:3".to_string(),
                "    #1 0x43bd27 in fuzzer::PrintStackTrace() /llvm-project-llvmorg-14.0.6/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:5".to_string(),
                "    #2 0x421f13 in fuzzer::Fuzzer::CrashCallback() /llvm-project-llvmorg-14.0.6/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:233:3".to_string(),
                "    #3 0x7ffff7dc641f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f) (BuildId: 7b4536f41cdaa5888408e82d0836e33dcf436466)".to_string(),
                "    #4 0x4c4540 in runtime.raise.abi0 runtime/sys_linux_amd64.s:158".to_string(),
                "".to_string(),
                "NOTE: libFuzzer has rudimentary signal handlers.".to_string(),
                "      Combine libFuzzer with AddressSanitizer or similar for better crash reports.".to_string(),
                "SUMMARY: libFuzzer: deadly signal".to_string(),
                "".to_string(),
            ],
            rust_report: vec![
                "Running: ./artifacts/fuzz_target_1/crash-da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
"thread '<unnamed>' panicked at fuzz_targets/fuzz_target_1.rs:6:9:".to_string(),
"index out of bounds: the len is 0 but the index is 10".to_string(),
"stack backtrace:".to_string(),
" 0:     0x557e259f793c - std::backtrace_rs::backtrace::libunwind::trace::h7d5a50c97105e9c9".to_string(),
"                             at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/../../backtrace/src/backtrace/libunwind.rs:93:5".to_string(),
" 1:     0x557e259f793c - std::backtrace_rs::backtrace::trace_unsynchronized::hf283bd0ba71b8b19".to_string(),
"                             at /rustc/59a8294849358a878a72358aa6d5fe5b9d312867/library/std/src/../../backtrace/src/backtrace/mod.rs:66:5".to_string(),
"                             at /home/toka/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libfuzzer-sys-0.4.7/libfuzzer/FuzzerMain.cpp:20:30".to_string(),
"2:     0x7ffbc33c6d90 - __libc_start_call_main".to_string(),
"                            at ./csu/../sysdeps/nptl/libc_start_call_main.h:58:16".to_string(),
"3:     0x7ffbc33c6e40 - __libc_start_main_impl".to_string(),
"                            at ./csu/../csu/libc-start.c:392:3".to_string(),
"4:     0x557e25886205 - _start".to_string(),
"5:                0x0 - <unknown>".to_string(),
            ],
            source: vec![
                "--->83             return utf16_to_utf8(std::u16string(name_array.begin(),".to_string(),
            ],
            execution_class: ExecutionClass {
                severity: "NOT_EXPLOITABLE".to_string(),
                short_description: "SourceAv".to_string(),
                description: "Access violation on source operand".to_string(),
                explanation: "The target crashed on an access violation at an address matching the source operand of the current instruction. This likely indicates a read access violation.".to_string(),
            },
            pid: 16476,
        };
        assert_eq!(
            159,
            format!("{report}").split('\n').collect::<Vec<&str>>().len()
        );
    }

    #[test]
    fn test_report_dedup() {
        let mut report = CrashReport::new();
        // Fill asan_report for correct parsing
        report.asan_report = vec!["".to_string()];
        report.stacktrace = vec![
            "#0 0x7ffff7b08c59  /build/glibc-SzIz7B/glibc-2.31/string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:345".to_string(),
            "#1 0x4db921 in __asan_memcpy /llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:22:3".to_string(),
            "#2 0x10c0819 in xlnt::detail::compound_document::read_directory() /xlnt/source/detail/cryptography/compound_document.cpp:975:34".to_string(),
            "#3 0x10bd55b in xlnt::detail::compound_document::compound_document(std::istream&) /xlnt/source/detail/cryptography/compound_document.cpp:517:5".to_string(),
            "#4 0x998b40 in (anonymous namespace)::decrypt_xlsx(std::vector<unsigned char, std::allocator<unsigned char> > const&, std::__cxx11::basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t> > const&) /xlnt/source/detail/cryptography/xlsx_crypto_consumer.cpp:320:37".to_string(),
        ];

        // Init ignored frames for correct filtering
        init_ignored_frames!("cpp");

        let res = dedup_reports(&[report.clone(), report.clone()]);
        let Ok(res) = res else {
            panic!("{}", res.err().unwrap());
        };
        assert!(res[0]);
        assert!(!res[1]);
    }

    #[test]
    fn test_report_cluster() {
        let mut report = CrashReport::new();
        // Fill asan_report for correct parsing
        report.asan_report = vec!["".to_string()];
        report.stacktrace = vec![
            "#0 0x7ffff7b08c59  /build/glibc-SzIz7B/glibc-2.31/string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:345".to_string(),
            "#1 0x4db921 in __asan_memcpy /llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:22:3".to_string(),
            "#2 0x10c0819 in xlnt::detail::compound_document::read_directory() /xlnt/source/detail/cryptography/compound_document.cpp:975:34".to_string(),
            "#3 0x10bd55b in xlnt::detail::compound_document::compound_document(std::istream&) /xlnt/source/detail/cryptography/compound_document.cpp:517:5".to_string(),
            "#4 0x998b40 in (anonymous namespace)::decrypt_xlsx(std::vector<unsigned char, std::allocator<unsigned char> > const&, std::__cxx11::basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t> > const&) /xlnt/source/detail/cryptography/xlsx_crypto_consumer.cpp:320:37".to_string(),
        ];

        // Init ignored frames for correct filtering
        init_ignored_frames!("cpp");

        let res = cluster_reports(&[report.clone(), report.clone()]);
        let Ok(res) = res else {
            panic!("{}", res.err().unwrap());
        };
        assert_eq!(res[0], 1);
        assert_eq!(res[1], 1);
    }
}
