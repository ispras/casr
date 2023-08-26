//! Report contains the main struct `CrashReport` with all information about crash.
use crate::asan::AsanStacktrace;
use crate::error;
use crate::error::*;
use crate::execution_class::*;
use crate::gdb::GdbStacktrace;
use crate::go::GoStacktrace;
use crate::java::JavaStacktrace;
use crate::python::PythonStacktrace;
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
    /// Dissassembly for crashed state (16 instructions).
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
    /// Timestamp.
    #[cfg_attr(feature = "serde", serde(skip_deserializing))]
    pub timestamp: i64,
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
        report.timestamp = local.timestamp_nanos();
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
            //TODO: Suport not only Debian-based packet managers
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
