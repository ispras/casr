use crate::error;
use crate::execution_class::*;
use chrono::prelude::*;
use gdb_command::registers::Registers;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::Command;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct CrashReport<'a> {
    /// Pid of crashed process.
    #[serde(skip)]
    pub pid: i32,
    /// Date and time of the problem report in ISO format. (see asctime(3)).
    #[serde(rename(serialize = "Date", deserialize = "Date"))]
    #[serde(default)]
    pub date: String,
    /// Output of uname -a.
    #[serde(rename(serialize = "Uname", deserialize = "Uname"))]
    #[serde(default)]
    pub uname: String,
    /// Name of the operating system. On LSB compliant systems, this can be determined with lsb_release -si.
    #[serde(rename(serialize = "OS", deserialize = "OS"))]
    #[serde(default)]
    pub os: String,
    /// Release version of the operating system. On LSB compliant systems, this can be determined with lsb_release -sr.
    #[serde(rename(serialize = "OSRelease", deserialize = "OSRelease"))]
    #[serde(default)]
    pub os_release: String,
    /// OS specific notation of processor/system architecture (e. g. i386).
    #[serde(rename(serialize = "Architecture", deserialize = "Architecture"))]
    #[serde(default)]
    pub architecture: String,
    /// Contents of /proc/pid/exe for ELF files; if the process is an interpreted script, this is the script path instead.
    #[serde(rename(serialize = "ExecutablePath", deserialize = "ExecutablePath"))]
    #[serde(default)]
    pub executable_path: String,
    /// Subset of the process’ environment, from /proc/pid/env; this should only show some standard variables that.
    /// Do not disclose potentially sensitive information, like $SHELL, $PATH, $LANG, and $LC_*
    #[serde(rename(serialize = "ProcEnviron", deserialize = "ProcEnviron"))]
    #[serde(default)]
    pub proc_environ: Vec<String>,
    /// Contents of /proc/pid/cmdline.
    #[serde(rename(serialize = "ProcCmdline", deserialize = "ProcCmdline"))]
    #[serde(default)]
    pub proc_cmdline: String,
    /// Contents of /proc/pid/status.
    #[serde(rename(serialize = "ProcStatus", deserialize = "ProcStatus"))]
    #[serde(default)]
    pub proc_status: Vec<String>,
    /// Contents of /proc/pid/maps.
    #[serde(rename(serialize = "ProcMaps", deserialize = "ProcMaps"))]
    #[serde(default)]
    pub proc_maps: Vec<String>,
    /// Opend files at crash : ls -lah /proc/<pid>/fd.
    #[serde(rename(serialize = "ProcFiles", deserialize = "ProcFiles"))]
    #[serde(default)]
    pub proc_fd: Vec<String>,
    /// Opened network connections.
    #[serde(rename(serialize = "NetworkConnections", deserialize = "NetworkConnections"))]
    #[serde(default)]
    pub network_connections: Vec<String>,
    /// Crash classification.
    #[serde(rename(serialize = "CrashSeverity", deserialize = "CrashSeverity"))]
    #[serde(default)]
    pub execution_class: ExecutionClass<'a>,
    /// Stack trace for crashed thread.
    #[serde(rename(serialize = "Stacktrace", deserialize = "Stacktrace"))]
    #[serde(default)]
    pub stacktrace: Vec<String>,
    /// Registers state for crashed thread.
    #[serde(rename(serialize = "Registers", deserialize = "Registers"))]
    #[serde(default)]
    pub registers: Registers,
    /// Dissassembly for crashed state (16 instructions).
    #[serde(rename(serialize = "Disassembly", deserialize = "Disassembly"))]
    #[serde(default)]
    pub disassembly: Vec<String>,
    /// Package name.
    #[serde(rename(serialize = "Package", deserialize = "Package"))]
    #[serde(default)]
    pub package: String,
    /// Package version.
    #[serde(rename(serialize = "PackageVersion", deserialize = "PackageVersion"))]
    #[serde(default)]
    pub package_version: String,
    /// Package architecture.
    #[serde(rename(serialize = "PackageArchitecture", deserialize = "PackageArchitecture"))]
    #[serde(default)]
    pub package_architecture: String,
    /// Package description.
    #[serde(rename(serialize = "PackageDescription", deserialize = "PackageDescription"))]
    #[serde(default)]
    pub package_description: String,
    /// Timestamp.
    #[serde(skip_deserializing)]
    pub timestamp: i64,
    /// asan report
    #[serde(rename(serialize = "AsanReport", deserialize = "AsanReport"))]
    #[serde(default)]
    pub asan_report: Vec<String>,
    #[serde(rename(serialize = "CrashLine", deserialize = "CrashLine"))]
    #[serde(default)]
    pub crashline: String,
    #[serde(rename(serialize = "Source", deserialize = "Source"))]
    #[serde(default)]
    pub source: Vec<String>,
}

impl<'a> CrashReport<'a> {
    /// Create new crash report.
    pub fn new() -> Self {
        let mut report: CrashReport = Default::default();
        let local: DateTime<Local> = Local::now();
        report.date = local.to_rfc3339_opts(SecondsFormat::Micros, false);
        report.timestamp = local.timestamp_nanos();
        report
    }

    /// Add information about opened network connections.
    pub fn add_network_connections(&mut self) -> error::Result<()> {
        let mut ss_cmd = Command::new("ss");
        ss_cmd.arg("-tuap");
        let ss_out = ss_cmd.output()?;
        if ss_out.status.success() {
            if let Ok(network_info) = String::from_utf8(ss_out.stdout) {
                self.network_connections = network_info
                    .split_terminator('\n')
                    .into_iter()
                    .map(|s| s.to_string())
                    .filter(|s| s.contains(&format!("pid={}", self.pid)))
                    .collect();
            }
        }

        Ok(())
    }
    /// Add OS info to the report.
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
    /// Add proc info to the report.
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
        self.proc_status = s
            .split_terminator('\n')
            .into_iter()
            .map(|s| s.to_string())
            .collect();

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
        self.proc_environ = s
            .split_terminator('\n')
            .into_iter()
            .map(|s| s.to_string())
            .collect();
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
        let possible_paths = vec![
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
                                    info.split_whitespace().into_iter().enumerate().for_each(
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
}

impl<'a> fmt::Display for CrashReport<'a> {
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
            for e in self.proc_environ.iter() {
                report += &format!("{}\n", e);
            }
        }

        // ProcCmdline
        if !self.proc_cmdline.is_empty() {
            report += &format!("\nProcCmdline: {}\n", &self.proc_cmdline);
        }

        // ProcStatus
        if !self.proc_status.is_empty() {
            report += "\n===ProcStatus===\n";
            for e in self.proc_status.iter() {
                report += &format!("{}\n", e);
            }
        }

        // ProcFiles
        if !self.proc_maps.is_empty() {
            report += "\n===ProcFiles===\n";
            for e in self.proc_maps.iter() {
                report += &format!("{}\n", e);
            }
        }

        // NetworkConnections
        if !self.proc_fd.is_empty() {
            report += "\n===NetworkConnections===\n";
            for e in self.proc_fd.iter() {
                report += &format!("{}\n", e);
            }
        }

        report += &format!("\n===CrashSeverity===\n{}\n", self.execution_class);

        // Stacktrace
        if !self.stacktrace.is_empty() {
            report += "\n===Stacktrace===\n";
            for e in self.stacktrace.iter() {
                report += &format!("{}\n", e);
            }
        }

        // Registers
        if !self.registers.is_empty() {
            report += "\n===CrashState===\n";
            for (reg, value) in &self.registers {
                report += &format!("{}:    0x{:x}\n", reg, value);
            }

            report += "\n";

            // Disassembly
            if !self.disassembly.is_empty() {
                for e in self.disassembly.iter() {
                    report += &format!("{}\n", e);
                }
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
            for e in self.asan_report.iter() {
                report += &format!("{}\n", e);
            }
        }

        // Source
        if !self.source.is_empty() {
            report += "\n===Source===\n";
            for e in self.source.iter() {
                report += &format!("{}\n", e);
            }
        }

        write!(f, "{}", report.trim())
    }
}
