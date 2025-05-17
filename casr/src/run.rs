use crate::{common, mode::Mode, run, util};
use libcasr::{
    gdb::{exploitable::MachineInfo, report::GdbCrash},
    report::{CrashReport, ReportExtractor},
    stacktrace::CrashLine,
};

use std::fs::File;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Arg, ArgAction, ArgGroup};
use gdb_command::{ExecType, GdbCommand};
use goblin::container::Endian;
use goblin::elf::{Elf, header};

pub fn gdb_run(
    argv: &[String],
    stdin: &Option<PathBuf>,
    timeout: u64,
    _ld_preload: &Option<String>, // TODO: Add support
    mode: &mut Mode,
) -> Result<(CrashReport, Box<dyn ReportExtractor>)> {
    let target_path = PathBuf::from(argv[0].clone());
    if !target_path.exists() {
        bail!("{} doesn't exist", target_path.to_str().unwrap());
    }
    // Prepare machine context
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
    // Elf header
    let elf_h = Elf::parse_header(&header).with_context(|| {
        format!(
            "Couldn't header for target binary: {}",
            target_path.display()
        )
    })?;
    // Machine info
    let mut machine = MachineInfo {
        arch: header::EM_X86_64,
        endianness: Endian::Little,
        byte_width: 8,
    };
    // Type should be executable or shared object.
    if elf_h.e_type != header::ET_EXEC && elf_h.e_type != header::ET_DYN {
        bail!("Target binary type should be executable or shared object");
    }
    // Byte width
    match elf_h.e_ident[4] {
        1 => machine.byte_width = 4,
        2 => machine.byte_width = 8,
        _ => {
            bail!("Couldn't determine byte_width: {}", elf_h.e_ident[4]);
        }
    }
    // Endianness
    if let Ok(endianness) = elf_h.endianness() {
        machine.endianness = endianness;
    } else {
        bail!("Couldn't get endianness from target binary");
    }
    // Architecture
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

    // Run gdb
    let args: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let exectype = ExecType::Local(&args);
    let mut gdb_command = GdbCommand::new(&exectype);
    let gdb_command = gdb_command
        .timeout(timeout)
        .stdin(stdin)
        .r()
        .bt()
        .siginfo()
        .mappings()
        .regs()
        // We need 2 disassembles: one for severity analysis
        // and another for the report.
        .mem("$pc", 64)
        .disassembly();

    // Get extractor
    let extractor = GdbCrash::new(gdb_command, machine)?;

    // Create report
    let mut report = common::get_report_stub(argv, stdin, mode)?;

    // Fill extra report fields
    report.proc_maps = extractor.proc_maps().to_vec();
    report.registers = extractor.registers().clone();
    report.set_disassembly(extractor.disassembly());

    Ok((report, Box::new(extractor)))
}

fn common_run(
    argv: &[String],
    stdin: &Option<PathBuf>,
    timeout: u64,
    ld_preload: &Option<String>,
    mode: &mut Mode,
) -> Result<Option<(CrashReport, Box<dyn ReportExtractor>)>> {
    // Run program.
    let mut cmd = Command::new(&argv[0]);
    // Set ld preload
    if let Some(ld_preload) = ld_preload {
        cmd.env("LD_PRELOAD", ld_preload);
    }
    if let Some(file) = stdin {
        cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    // Update mode-dependent characteristics
    common::update_cmd(&mut cmd, mode);
    // Get output
    let result = util::get_output(&mut cmd, timeout, true)?;
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    let signal = result.status.signal();

    // Create report
    let report = common::get_report_stub(argv, stdin, mode)?;
    // Get report extractor
    let Some(extractor) = common::get_extractor(&stdout, &stderr, signal, mode)? else {
        return Ok(None);
    };
    Ok(Some((report, extractor)))
}

pub fn run(
    argv: &[String],
    stdin: &Option<PathBuf>,
    timeout: u64,
    ld_preload: &Option<String>,
    mode: &mut Mode,
) -> Result<(CrashReport, Box<dyn ReportExtractor>)> {
    if let Mode::Gdb = mode {
        gdb_run(argv, stdin, timeout, ld_preload, mode)
    } else if let Some((report, extractor)) = common_run(argv, stdin, timeout, ld_preload, mode)? {
        Ok((report, extractor))
    } else {
        gdb_run(argv, stdin, timeout, ld_preload, mode)
    }
}

pub fn casr(args: &[String], mode: Option<Mode>) -> Result<()> {
    let matches = clap::Command::new("casr")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from target output")
        .term_width(90)
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .global(true)
                .group("out")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("REPORT")
                .help(
                    "Path to save report. Path can be a directory, then report name is generated",
                ),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .global(true)
                .group("out")
                .action(ArgAction::SetTrue)
                .help("Print CASR report to stdout"),
        )
        .group(
            ArgGroup::new("out")
                .args(["stdout", "output"])
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("Stdin file for program"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .short('t')
                .global(true)
                .action(ArgAction::Set)
                .default_value("0")
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution, 0 value means that timeout is disabled")
                .value_parser(clap::value_parser!(u64))
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        .arg(
            Arg::new("strip-path")
                .long("strip-path")
                .env("CASR_STRIP_PATH")
                .global(true)
                .action(ArgAction::Set)
                .value_name("PREFIX")
                .help("Path prefix to strip from stacktrace"),
        )
        .arg(
            Arg::new("ld-preload")
                .long("ld-preload")
                .env("CASR_PRELOAD")
                .global(true)
                .action(ArgAction::Set)
                .num_args(1..)
                .value_name("LIBS")
                .value_parser(clap::value_parser!(String))
                .help("Set LD_PRELOAD for the target program without disrupting the CASR process itself (both ` ` and `:` are valid delimiter)")
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                .global(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .subcommands([
            clap::Command::new("auto")
                .about("Auto define proper way to threat target output (default behavior)"),
            clap::Command::new("csharp")
                .about("Threat target output as C# reports"),
            clap::Command::new("gdb")
                .about("Create report from gdb execution"),
            clap::Command::new("go")
                .about("Threat target output as Go reports"),
            clap::Command::new("java")
                .about("Threat target output as Java reports")
                .arg(
                    Arg::new("source-dirs")
                        .long("source-dirs")
                        .env("CASR_SOURCE_DIRS")
                        .action(ArgAction::Set)
                        .num_args(1..)
                        .value_delimiter(':')
                        .value_parser(clap::value_parser!(PathBuf))
                        .value_name("DIR")
                        .help("Paths to directories with Java source files (list separated by ':' for env)"),
                ),
            clap::Command::new("js")
                .about("Threat target output as JS reports"),
            clap::Command::new("lua")
                .about("Threat target output as Lua reports"),
            clap::Command::new("python")
                .about("Threat target output as Python or Atheris reports"),
            clap::Command::new("rust")
                .about("Threat target output as Rust reports"),
            clap::Command::new("san")
                .about("Threat target output as AddressSanitizer or MemorySanitizer reports"),
            clap::Command::new("asan")
                .about("Threat target output as AddressSanitizer reports"),
            clap::Command::new("msan")
                .about("Threat target output as MemorySanitizer reports"),
        ])
        .get_matches_from(args);

    // Check required global args
    // NOTE: Combine `global` and `required` qualifiers is forbidden
    util::check_required(&matches, &["out", "ARGS"])?;
    // Get program args.
    let mut argv: Vec<String> = if let Some(argv) = matches.get_many::<String>("ARGS") {
        argv.map(|arg| arg.as_str().to_string()).collect()
    } else {
        bail!("Wrong arguments for starting program");
    };
    // Get stdin for target program.
    let stdin = util::stdin_from_matches(&matches)?;
    // Get timeout
    let timeout = *matches.get_one::<u64>("timeout").unwrap();
    // Get ld preload
    let ld_preload = util::get_ld_preload(&matches);
    // Get subcommand args
    let submatches = if let Some(name) = matches.subcommand_name() {
        matches.subcommand_matches(name)
    } else {
        None
    };
    // Get mode
    let mut mode = match mode {
        Some(mode) => mode,
        None => Mode::from(matches.subcommand_name(), &argv)?,
    };

    // Prepare run
    common::prepare_run(&mut argv, &mode)?;

    // Set ignored frames
    if let Some(path) = matches.get_one::<PathBuf>("ignore") {
        util::add_custom_ignored_frames(path)?;
    }

    // Get report
    let (mut report, mut extractor) = run::run(&argv, &stdin, timeout, &ld_preload, &mut mode)?;
    // Extract report
    common::fill_report(&mut report, extractor.report(), &mode);
    report.stacktrace = extractor.extract_stacktrace()?;
    let execution_class = extractor.execution_class();
    match execution_class {
        Ok(execution_class) => {
            report.execution_class = execution_class;
        }
        Err(err) => {
            eprintln!("Couldn't estimate severity. {}", err);
        }
    }
    if let Ok(crashline) = extractor.crash_line() {
        report.crashline = crashline.to_string();
        if let CrashLine::Source(debug) = crashline {
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
            // Modify DebugInfo to find sources (for Java)
            common::update_sources(&mut report, debug, &submatches, &mode);
        }
    }
    // Strip paths
    let stacktrace = extractor.parse_stacktrace()?;
    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }

    // Check for exceptions
    common::check_exception(&mut report, extractor.stream(), &mode);

    // Output report
    util::output_report(&report, &matches, &argv)
}
