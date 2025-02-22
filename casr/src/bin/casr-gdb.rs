use casr::util;
use libcasr::{
    cpp::CppException,
    exception::Exception,
    gdb::GdbStacktrace,
    gdb::exploitable::{GdbContext, MachineInfo},
    init_ignored_frames,
    report::CrashReport,
    rust::RustPanic,
    severity::Severity,
    stacktrace::*,
};

use anyhow::{Context, Result, bail};
use clap::{Arg, ArgAction, ArgGroup};
use gdb_command::mappings::*;
use gdb_command::memory::*;
use gdb_command::registers::*;
use gdb_command::siginfo::Siginfo;
use gdb_command::stacktrace::StacktraceExt;
use gdb_command::*;
use goblin::container::Endian;
use goblin::elf::{Elf, header};
use regex::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-gdb")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from gdb execution")
        .term_width(90)
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .action(ArgAction::Set)
                .value_name("REPORT")
                .value_parser(clap::value_parser!(PathBuf))
                .help(
                    "Path to save report. Path can be a directory, then report name is generated",
                ),
        )
        .arg(
            Arg::new("stdout")
                .action(ArgAction::SetTrue)
                .long("stdout")
                .help("Print CASR report to stdout"),
        )
        .group(
            ArgGroup::new("out")
                .args(["stdout", "output"])
                .required(true),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .action(ArgAction::Set)
                .value_name("FILE")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Stdin file for program"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .action(ArgAction::Set)
                .default_value("0")
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution, 0 value means that timeout is disabled")
                .value_parser(clap::value_parser!(u64))
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .action(ArgAction::Set)
                .value_name("FILE")
                .value_parser(clap::value_parser!(PathBuf))
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        .arg(
            Arg::new("strip-path")
                .long("strip-path")
                .env("CASR_STRIP_PATH")
                .action(ArgAction::Set)
                .value_name("PREFIX")
                .help("Path prefix to strip from stacktrace and crash line"),
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                .required(true)
                .help("Add \"-- ./binary <arguments>\" to run executable"),
        )
        .get_matches();

    // Get program args.
    let argv: Vec<&str> = if let Some(argvs) = matches.get_many::<String>("ARGS") {
        argvs.map(|s| s.as_str()).collect()
    } else {
        bail!("Wrong arguments for starting program");
    };

    // Get timeout
    let timeout = *matches.get_one::<u64>("timeout").unwrap();

    init_ignored_frames!("cpp", "rust");
    if let Some(path) = matches.get_one::<PathBuf>("ignore") {
        util::add_custom_ignored_frames(path)?;
    }
    // Get stdin for target program.
    let stdin_file = util::stdin_from_matches(&matches)?;

    let target_path = PathBuf::from(argv[0]);
    if !target_path.exists() {
        bail!("{} doesn't exist", target_path.to_str().unwrap());
    }

    let mut header = vec![0u8; 64];
    // The ELF header is 52 or 64 bytes long for 32-bit and 64-bit binaries respectively.
    let mut file = File::open(&target_path)
        .with_context(|| format!("Couldn't open target binary: {}", target_path.display()))?;
    file.read_exact(&mut header).with_context(|| {
        format!(
            "Couldn't read target binary header: {}",
            target_path.display()
        )
    })?;

    let mut report = CrashReport::new();
    report.executable_path = argv[0].to_string();
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();
    if let Some(mut file_path) = stdin_file.clone() {
        file_path = file_path.canonicalize().unwrap_or(file_path);
        report.stdin = file_path.display().to_string();
    }
    let elf_h = Elf::parse_header(&header).with_context(|| {
        format!(
            "Couldn't header for target binary: {}",
            target_path.display()
        )
    })?;

    let mut machine = MachineInfo {
        arch: header::EM_X86_64,
        endianness: Endian::Little,
        byte_width: 8,
    };

    // Type should be executable or shared object.
    if elf_h.e_type != header::ET_EXEC && elf_h.e_type != header::ET_DYN {
        bail!("Target binary type should be executable or shared object");
    }

    match elf_h.e_ident[4] {
        1 => machine.byte_width = 4,
        2 => machine.byte_width = 8,
        _ => {
            bail!("Couldn't determine byte_width: {}", elf_h.e_ident[4]);
        }
    }

    if let Ok(endianness) = elf_h.endianness() {
        machine.endianness = endianness;
    } else {
        bail!("Couldn't get endianness from target binary");
    }

    match elf_h.e_machine {
        header::EM_386
        | header::EM_ARM
        | header::EM_X86_64
        | header::EM_AARCH64
        | header::EM_RISCV => machine.arch = elf_h.e_machine,
        _ => {
            bail!("Unsupported architecture: {}", elf_h.e_machine);
        }
    }
    let exectype = ExecType::Local(argv.as_slice());
    let mut gdb_command = GdbCommand::new(&exectype);
    let gdb_command = gdb_command
        .timeout(timeout)
        .stdin(&stdin_file)
        .r()
        .bt()
        .siginfo()
        .mappings()
        .regs()
        // We need 2 disassembles: one for severity analysis
        // and another for the report.
        .mem("$pc", 64)
        .disassembly();

    let stdout = gdb_command
        .raw()
        .with_context(|| "Unable to get results from gdb")?;

    let output = String::from_utf8_lossy(&stdout);

    let result = gdb_command.parse(&output)?;
    report.stacktrace = GdbStacktrace::extract_stacktrace(&result[0])?;
    report.proc_maps = result[2]
        .split('\n')
        .skip(3)
        .map(|x| x.to_string())
        .collect();

    let siginfo = Siginfo::from_gdb(&result[1]);

    if let Err(error) = siginfo {
        let err_str = error.to_string();
        let re = Regex::new(r"\$\d+ = (0x0|void) doesn't match regex template").unwrap();
        if err_str.contains(":  doesn't match") || re.is_match(&err_str) {
            // Normal termination.
            bail!("Program terminated (no crash)");
        } else {
            return Err(error.into());
        }
    }

    let context = GdbContext {
        siginfo: siginfo.unwrap(),
        mappings: MappedFiles::from_gdb(&result[2])?,
        registers: Registers::from_gdb(&result[3])?,
        pc_memory: MemoryObject::from_gdb(&result[4])?,
        machine,
        stacktrace: report.stacktrace.clone(),
    };

    report.set_disassembly(&result[5]);

    let severity = context.severity();

    if let Ok(severity) = severity {
        report.execution_class = severity;
    } else {
        eprintln!("Couldn't estimate severity. {}", severity.err().unwrap());
    }

    // Check for exceptions
    if let Some(class) = [CppException::parse_exception, RustPanic::parse_exception]
        .iter()
        .find_map(|parse| parse(&output))
    {
        report.execution_class = class;
    }

    report.registers = context.registers;

    let mut parsed_stacktrace = GdbStacktrace::parse_stacktrace(&report.stacktrace)?;
    if let Ok(mfiles) = MappedFiles::from_gdb(report.proc_maps.join("\n")) {
        parsed_stacktrace.compute_module_offsets(&mfiles);
    }
    // Get crash line.
    if let Ok(crash_line) = parsed_stacktrace.crash_line() {
        report.crashline = crash_line.to_string();
        if let CrashLine::Source(debug) = crash_line {
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
        }
    }

    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &parsed_stacktrace, path);
    }

    //Output report
    util::output_report(&report, &matches, &argv)
}
