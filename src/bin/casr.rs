extern crate anyhow;
#[macro_use]
extern crate log;
extern crate casr;
extern crate chrono;
extern crate clap;
extern crate gdb_command;
extern crate goblin;
extern crate libc;
extern crate nix;
extern crate serde;
extern crate serde_json;
extern crate simplelog;

use anyhow::{bail, Context, Result};
use clap::{App, Arg, ArgGroup};
use gdb_command::mappings::{MappedFiles, MappedFilesExt};
use gdb_command::registers::{Registers, RegistersExt};
use gdb_command::siginfo::Siginfo;
use gdb_command::{ExecType, GdbCommand};
use goblin::container::Endian;
use goblin::elf::{header, note, Elf};
use nix::fcntl::{flock, FlockArg};
use simplelog::*;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{self, Read};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use casr::analysis;
use casr::analysis::{CrashContext, MachineInfo};
use casr::error::Error;
use casr::report::*;

fn main() -> Result<()> {
    let matches = App::new("casr")
        .version("2.0.0")
        .author("Andrey Fedotov  <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>")
        .about("Analyze coredump for security goals and provide detailed report with severity estimation")
        .term_width(90)
        .arg(Arg::new("mode")
            .short('m')
            .long("mode")
            .takes_value(true)
            .value_name("MODE")
            .possible_values(&["online", "offline"])
            .default_value("offline")
            .help("Offline mode analyzes collected coredumps, online mode intercepts coredumps via core_pattern")
)
        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .value_name("FILE")
            .help("Path to input core file")
            .required_if_eq("mode","offline")
            .takes_value(true))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .value_name("FILE")
            .help("Path to save report in JSON format")
            .takes_value(true))
        .arg(Arg::new("stdout")
            .long("stdout")
            .help("Print CASR report to stdout")
            )
        .arg(Arg::new("core")
            .help("Core file size soft resource limit of crashing process")
            .short('c')
            .long("core")
            .takes_value(true)
            .hide(true)
            .value_name("LIMIT"))
        .arg(Arg::new("executable")
            .short('e')
            .long("executable")
            .value_name("FILE")
            .help("Path to executable")
            .takes_value(true))
        .arg(Arg::new("uid")
            .short('u')
            .long("uid")
            .hide(true)
            .value_name("UID")
            .help("(Numeric) real UID of dumped process")
            .takes_value(true))
        .arg(Arg::new("pid")
            .short('p')
            .long("pid")
            .hide(true)
            .value_name("PID")
            .help("PID of dumped process, as seen in the PID namespace in which the process resides")
            .takes_value(true))
        .arg(Arg::new("gid")
            .short('g')
            .hide(true)
            .long("gid")
            .value_name("GID")
            .help("(Numeric) Real GID of dumped process")
            .takes_value(true))
        .arg(Arg::new("hpid")
            .short('P')
            .hide(true)
            .long("host-pid")
            .value_name("HPID")
            .help("PID of dumped process, as seen in the initial PID namespace (since Linux 3.12)")
            .takes_value(true))
        .group(ArgGroup::new("online_analysis")
            .args(&["core","uid","pid", "hpid"])
            .multiple(true)
            .conflicts_with_all(&["offline_analysis"]))
        .group(ArgGroup::new("offline_analysis")
            .args(&["file","output"])
            .arg("stdout")
            .multiple(true)
            .conflicts_with_all(&["online_analysis"]))
        .get_matches();

    let mode = matches.value_of("mode").unwrap();
    if mode == "offline" {
        if !matches.is_present("output") && !matches.is_present("stdout") {
            bail!("--stdout or --output should be specified in offline mode.");
        }

        let core_path = PathBuf::from(matches.value_of("file").unwrap());
        if !core_path.exists() {
            bail!("{} doesn't exist", core_path.to_str().unwrap());
        }

        let mut core: Vec<u8> = Vec::new();
        let mut file = File::open(&core_path)
            .with_context(|| format!("Couldn't open core: {}", core_path.display()))?;
        file.read_to_end(&mut core)
            .with_context(|| format!("Couldn't read core: {}", core_path.display()))?;
        let mut report = CrashReport::new();

        if matches.is_present("executable") {
            let executable_path = PathBuf::from(matches.value_of("executable").unwrap());
            if !executable_path.exists() {
                bail!("{} doesn't exist", executable_path.to_str().unwrap());
            }
            report
                .executable_path
                .push_str(executable_path.to_str().unwrap());
        }
        let result = analyze_coredump(&mut report, &core, &core_path);
        if result.is_ok() {
            if matches.is_present("output") {
                let result_path = PathBuf::from(matches.value_of("output").unwrap());
                let mut file = File::create(&result_path).with_context(|| {
                    format!("Couldn't create report: {}", result_path.display())
                })?;
                file.write_all(serde_json::to_string_pretty(&report).unwrap().as_bytes())
                    .with_context(|| format!("Couldn't write report: {}", result_path.display()))?;
            }

            if matches.is_present("stdout") {
                println!("{}\n", serde_json::to_string_pretty(&report).unwrap());
            }
        } else {
            bail!("Coredump analysis error: {}", result.err().unwrap());
        }
        return Ok(());
    }

    // Online mode.
    WriteLogger::init(
        LevelFilter::Info,
        ConfigBuilder::new().set_time_to_local(true).build(),
        OpenOptions::new()
            .append(true)
            .create(true)
            .open("/var/log/casr.log")?,
    )
    .unwrap();

    let casr_cmd = std::env::args().collect::<Vec<String>>().join(" ");

    // Analyze multiple crashes one by one
    let lockfile = check_lock();
    if lockfile.is_err() {
        error!(
            "Cannot open Casr.lock file: {}. Casr command line: {}",
            lockfile.as_ref().err().unwrap(),
            &casr_cmd
        );
        bail!(
            "Cannot open Casr.lock file: {}. Casr command line: {}",
            lockfile.as_ref().err().unwrap(),
            &casr_cmd
        );
    }

    let executable_path = PathBuf::from(
        matches
            .value_of("executable")
            .unwrap()
            .chars()
            .map(|c| if c == '!' { '/' } else { c })
            .collect::<String>(),
    );
    let pid = matches.value_of("pid").unwrap().parse::<i32>().unwrap();
    let culimit = matches
        .value_of("core")
        .unwrap_or("0")
        .parse::<i32>()
        .unwrap_or(-1);
    let uid = matches.value_of("uid").unwrap().parse::<u32>().unwrap();
    let gid = matches.value_of("gid").unwrap().parse::<u32>().unwrap();
    let mut file_name_to_save = matches
        .value_of("executable")
        .unwrap()
        .chars()
        .map(|c| if c == '!' { '_' } else { c })
        .collect::<String>();

    // Create output file prefix.
    let mut report = CrashReport::new();
    report.pid = pid;
    // Add network connections.
    if let Err(error) = report.add_network_connections() {
        error!("{}", error.to_string());
    }

    file_name_to_save.push_str(&format!("_{}", report.date));
    let mut core_path = PathBuf::new();
    core_path.push(format!("/var/crash/{}.core", file_name_to_save));
    let mut report_path = PathBuf::new();
    report_path.push(format!("/var/crash/{}.casrep", file_name_to_save));

    report
        .executable_path
        .push_str(executable_path.to_str().unwrap());

    // Add OS information.
    if let Err(error) = report.add_os_info() {
        error!("{}. Casr command line: {}", error.to_string(), &casr_cmd);
    }

    // Add process information.
    if let Err(error) = report.add_proc_info() {
        error!("{}. Casr command line: {}", error.to_string(), &casr_cmd);
    }

    // Add package information.
    if let Err(error) = report.add_package_info() {
        error!("{}. Casr command line: {}", error.to_string(), &casr_cmd);
    }

    // Drop privileges.
    unsafe {
        libc::setuid(uid);
        libc::setgid(gid);
    }

    let mut core: Vec<u8> = Vec::new();
    if culimit < 0 || (core.len() as i32) < culimit {
        // Ulimit is unlimited or core is smaller.
        io::stdin().read_to_end(&mut core)?;
        File::create(&core_path)?.write_all(&core)?;
    } else {
        // Core is larger then ulimit is set.
        core = vec![0u8; culimit as usize];
        io::stdin().read_exact(&mut core)?;
        File::create(&core_path)?.write_all(&core)?;
    }

    if culimit == 0 {
        error!("Ulimit is set to 0. Set ulimit greater than zero to analyze coredumps. Casr command line: {}", &casr_cmd);
    }
    let result = analyze_coredump(&mut report, &core, &core_path);
    if result.is_err() {
        error!(
            "Coredump analysis error: {}. Casr command line: {}",
            result.as_ref().err().unwrap(),
            &casr_cmd
        );
        bail!(
            "Coredump analysis error: {}. Casr command line: {}",
            result.as_ref().err().unwrap(),
            &casr_cmd
        );
    }

    // Save report.
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&report_path)
    {
        file.write_all(serde_json::to_string_pretty(&report).unwrap().as_bytes())?;
    } else {
        error!("Couldn't write report file: {}", report_path.display());
    }
    drop(lockfile.unwrap());
    Ok(())
}

/// Method checks mutex.
fn check_lock() -> Result<File> {
    let mut project_dir = PathBuf::from("/var/crash/");
    project_dir.push("Casr.lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(project_dir)?;
    let fd = file.as_raw_fd();
    flock(fd, FlockArg::LockExclusive).unwrap();
    Ok(file)
}

/// Analyze coredump and put information to report.
///
/// # Arguments
///
/// * `report` - Crash report.
///
/// * `core` - binary coredump.
///
/// * `core_path` - path to core file.
fn analyze_coredump(
    report: &mut CrashReport,
    core: &[u8],
    core_path: &Path,
) -> casr::error::Result<()> {
    let mut machine = MachineInfo {
        arch: header::EM_X86_64,
        endianness: Endian::Little,
        byte_width: 8,
    };

    // Parse coredump.
    let elf = Elf::parse(core)?;

    // Type should be CORE.
    if elf.header.e_type != header::ET_CORE {
        return Err(Error::Casr("Core should be an ELF file.".to_string()));
    }

    let notes_iter = elf.iter_note_headers(core);

    if notes_iter.is_none() {
        return Err(Error::Casr(
            "Notes section are empty in coredump.".to_string(),
        ));
    }

    match elf.header.e_ident[4] {
        1 => machine.byte_width = 4,
        2 => machine.byte_width = 8,
        _ => {
            return Err(Error::Casr(format!(
                "Couldn't determine byte_width: {}",
                elf.header.e_ident[4]
            )))
        }
    }

    if let Ok(endianness) = elf.header.endianness() {
        machine.endianness = endianness;
    } else {
        return Err(Error::Casr("Couldn't get endianness from core".to_string()));
    }

    match elf.header.e_machine {
        header::EM_386 | header::EM_ARM | header::EM_X86_64 => machine.arch = elf.header.e_machine,
        _ => {
            return Err(Error::Casr(format!(
                "Unsupported architecture: {}",
                elf.header.e_machine
            )))
        }
    }

    let notes_iter = notes_iter.unwrap();

    for note in notes_iter.flatten() {
        if note.n_type == note::NT_PRPSINFO {
            // Get run command.
            let mut run_line = String::new();
            match elf.header.e_machine {
                header::EM_386 | header::EM_ARM => {
                    if note.desc.len() < 45 {
                        warn!("Prpsinfo is less than 45 bytes.");
                        break;
                    }
                    for b in &note.desc[44..note.desc.len()] {
                        if *b != 0x0 {
                            run_line.push(*b as char);
                        } else {
                            break;
                        }
                    }
                }
                header::EM_X86_64 => {
                    if note.desc.len() < 57 {
                        warn!("Prpsinfo is less than 57 bytes.");
                        break;
                    }
                    for b in &note.desc[56..note.desc.len()] {
                        if *b != 0x0 {
                            run_line.push(*b as char);
                        } else {
                            break;
                        }
                    }
                }
                _ => {}
            };

            if report.proc_cmdline.is_empty() {
                report.proc_cmdline = run_line.clone();
            }
        }
    }

    let result = GdbCommand::new(&ExecType::Core {
        target: &report.executable_path,
        core: core_path.to_str().unwrap(),
    })
    .bt()
    .siginfo()
    .mappings()
    .regs()
    .launch()?;

    report.stacktrace = result[0].split('\n').map(|x| x.to_string()).collect();
    if report.proc_maps.is_empty() {
        report.proc_maps = result[2]
            .split('\n')
            .skip(3)
            .map(|x| x.to_string())
            .collect();
    }

    let mut context = CrashContext {
        siginfo: Siginfo::from_gdb(&result[1])?,
        mappings: MappedFiles::from_gdb(&result[2])?,
        registers: Registers::from_gdb(&result[3])?,
        machine,
    };

    // Set executable path from user.
    if !report.executable_path.is_empty() {
        let path = PathBuf::from(report.executable_path.clone());
        // Change executable path in mfiles.
        let name = path.file_name().unwrap().to_str().unwrap();
        context.mappings = context
            .mappings
            .iter()
            .cloned()
            .map(|f| {
                if f.name.contains(name) {
                    gdb_command::mappings::File::new(
                        f.start,
                        f.end,
                        f.offset,
                        &report.executable_path,
                    )
                } else {
                    f
                }
            })
            .collect();
    }

    let result = analysis::severity(report, &context)?;

    report.execution_class = result.clone();
    report.registers = context.registers;

    Ok(())
}
