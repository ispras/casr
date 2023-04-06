use anyhow::{bail, Context, Result};
use clap::{Arg, ArgAction, ArgGroup};
use gdb_command::mappings::{MappedFiles, MappedFilesExt};
use gdb_command::memory::*;
use gdb_command::registers::{Registers, RegistersExt};
use gdb_command::siginfo::Siginfo;
use gdb_command::{ExecType, GdbCommand};
use goblin::container::Endian;
use goblin::elf::{header, note, Elf};
use log::{error, warn};
use nix::fcntl::{flock, FlockArg};
use simplelog::*;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{self, Read};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use libcasr::error::Error;
use libcasr::gdb::exploitable::{GdbContext, MachineInfo};
use libcasr::report::*;
use libcasr::severity::Severity;

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-core")
        .color(clap::ColorChoice::Auto)
        .version("2.5.1")
        .author("Andrey Fedotov <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>")
        .about("Analyze coredump for security goals and provide detailed report with severity estimation")
        .term_width(90)
        .arg(Arg::new("mode")
            .short('m')
            .long("mode")
            .action(ArgAction::Set)
            .value_name("MODE")
            .value_parser(["online", "offline"])
            .default_value("offline")
            .help("Offline mode analyzes collected coredumps, online mode intercepts coredumps via core_pattern")
)
        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .value_name("FILE")
            .help("Path to input core file")
            .required_if_eq("mode","offline")
            .action(ArgAction::Set))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .value_name("FILE")
            .help("Path to save report in JSON format")
            .action(ArgAction::Set))
        .arg(Arg::new("stdout")
            .long("stdout")
            .action(ArgAction::SetTrue)
            .help("Print CASR report to stdout")
            )
        .arg(Arg::new("core")
            .help("Core file size soft resource limit of crashing process")
            .short('c')
            .long("core")
            .action(ArgAction::Set)
            .hide(true)
            .value_name("LIMIT"))
        .arg(Arg::new("executable")
            .short('e')
            .long("executable")
            .value_name("FILE")
            .help("Path to executable")
            .action(ArgAction::Set))
        .arg(Arg::new("uid")
            .short('u')
            .long("uid")
            .hide(true)
            .value_name("UID")
            .help("(Numeric) real UID of dumped process")
            .action(ArgAction::Set))
        .arg(Arg::new("pid")
            .short('p')
            .long("pid")
            .hide(true)
            .value_name("PID")
            .help("PID of dumped process, as seen in the PID namespace in which the process resides")
            .action(ArgAction::Set))
        .arg(Arg::new("gid")
            .short('g')
            .hide(true)
            .long("gid")
            .value_name("GID")
            .help("(Numeric) Real GID of dumped process")
            .action(ArgAction::Set))
        .arg(Arg::new("hpid")
            .short('P')
            .hide(true)
            .long("host-pid")
            .value_name("HPID")
            .help("PID of dumped process, as seen in the initial PID namespace (since Linux 3.12)")
            .action(ArgAction::Set))
        .group(ArgGroup::new("online_analysis")
            .args(["core","uid","pid", "hpid"])
            .multiple(true)
            .conflicts_with_all(["offline_analysis"]))
        .group(ArgGroup::new("offline_analysis")
            .args(["file","output"])
            .arg("stdout")
            .multiple(true)
            .conflicts_with_all(["online_analysis"]))
        .get_matches();

    let mode = matches.get_one::<String>("mode").unwrap();
    if *mode == "offline" {
        if !matches.contains_id("output") && !matches.contains_id("stdout") {
            bail!("--stdout or --output should be specified in offline mode.");
        }

        let core_path = PathBuf::from(matches.get_one::<String>("file").unwrap());
        if !core_path.exists() {
            bail!("{} doesn't exist", core_path.to_str().unwrap());
        }

        let mut core: Vec<u8> = Vec::new();
        let mut file = File::open(&core_path)
            .with_context(|| format!("Couldn't open core: {}", core_path.display()))?;
        file.read_to_end(&mut core)
            .with_context(|| format!("Couldn't read core: {}", core_path.display()))?;
        let mut report = CrashReport::new();

        if matches.contains_id("executable") {
            let executable_path = PathBuf::from(matches.get_one::<String>("executable").unwrap());
            if !executable_path.exists() {
                bail!("{} doesn't exist", executable_path.to_str().unwrap());
            }
            report
                .executable_path
                .push_str(executable_path.to_str().unwrap());
        }

        let result = analyze_coredump(&mut report, &core, &core_path);

        if result.is_ok() {
            if matches.contains_id("output") {
                let result_path = PathBuf::from(matches.get_one::<String>("output").unwrap());
                let mut file = File::create(&result_path).with_context(|| {
                    format!("Couldn't create report: {}", result_path.display())
                })?;
                file.write_all(serde_json::to_string_pretty(&report).unwrap().as_bytes())
                    .with_context(|| format!("Couldn't write report: {}", result_path.display()))?;
            }

            if matches.get_flag("stdout") {
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
        ConfigBuilder::new()
            .set_time_offset_to_local()
            .unwrap()
            .build(),
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
            .get_one::<String>("executable")
            .unwrap()
            .chars()
            .map(|c| if c == '!' { '/' } else { c })
            .collect::<String>(),
    );
    let pid = *matches.get_one::<i32>("pid").unwrap();
    let culimit = *matches.get_one::<i32>("core").unwrap_or(&-1);
    let uid = *matches.get_one::<u32>("uid").unwrap();
    let gid = *matches.get_one::<u32>("gid").unwrap();
    let mut file_name_to_save = matches
        .get_one::<String>("executable")
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
    core_path.push(format!("/var/crash/{file_name_to_save}.core"));
    let mut report_path = PathBuf::new();
    report_path.push(format!("/var/crash/{file_name_to_save}.casrep"));

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

    if culimit == 0 {
        error!("Ulimit is set to 0. Set ulimit greater than zero to analyze coredumps. Casr command line: {}", &casr_cmd);
        drop(lockfile.unwrap());
        bail!("Ulimit is set to 0. Set ulimit greater than zero to analyze coredumps. Casr command line: {}", &casr_cmd);
    }

    let core = if culimit < 0 {
        // Ulimit is unlimited.
        let mut core = Vec::new();
        io::stdin().read_to_end(&mut core)?;
        File::create(&core_path)?.write_all(&core)?;
        core
    } else {
        // Ulimit is set.
        let mut core = Vec::new();
        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        let mut total_bytes = 0_usize;
        while total_bytes < culimit as usize {
            let buffer = stdin.fill_buf().unwrap();
            let len = buffer.len();
            if len == 0 {
                break;
            }
            core.extend_from_slice(buffer);
            total_bytes += len;
        }
        File::create(&core_path)?.write_all(&core)?;
        core
    };
    let result = analyze_coredump(&mut report, &core, &core_path);
    if result.is_err() {
        error!(
            "Coredump analysis error: {}. Casr command line: {}",
            result.as_ref().err().unwrap(),
            &casr_cmd
        );
        drop(lockfile.unwrap());
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
) -> libcasr::error::Result<()> {
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
        header::EM_386 | header::EM_ARM | header::EM_X86_64 | header::EM_AARCH64 => {
            machine.arch = elf.header.e_machine
        }
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
            match machine.byte_width {
                4 => {
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
                8 => {
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
    // We need 2 disassembles: one for severity analysis
    // and another for the report.
    .mem("$pc", 64)
    .disassembly()
    .launch()?;

    report.stacktrace = result[0].split('\n').map(|x| x.to_string()).collect();
    if report.proc_maps.is_empty() {
        report.proc_maps = result[2]
            .split('\n')
            .skip(3)
            .map(|x| x.to_string())
            .collect();
    }

    let mut context = GdbContext {
        siginfo: Siginfo::from_gdb(&result[1])?,
        mappings: MappedFiles::from_gdb(&result[2])?,
        registers: Registers::from_gdb(&result[3])?,
        pc_memory: MemoryObject::from_gdb(&result[4])?,
        machine,
        stacktrace: report.stacktrace.clone(),
    };

    report.set_disassembly(&result[5]);

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

    let severity = context.severity();

    if let Ok(severity) = severity {
        report.execution_class = severity;
    } else {
        warn!("Couldn't estimate severity. {}", severity.err().unwrap());
    }

    report.registers = context.registers;

    Ok(())
}
