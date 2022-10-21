extern crate anyhow;
extern crate casr;
extern crate clap;
extern crate gdb_command;

use casr::analysis;
use casr::analysis::{CrashContext, MachineInfo};
use casr::debug;
use casr::debug::CrashLine;
use casr::report::CrashReport;

use anyhow::{bail, Context, Result};
use clap::{App, Arg, ArgGroup};
use gdb_command::mappings::*;
use gdb_command::registers::*;
use gdb_command::siginfo::Siginfo;
use gdb_command::*;
use goblin::container::Endian;
use goblin::elf::{header, Elf};
use regex::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

fn main() -> Result<()> {
    let matches = App::new("casr-gdb")
        .version("2.1.0")
        .author("Andrey Fedotov  <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>")
        .about("Create CASR reports (.casrep) from gdb execution")
        .term_width(90)
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .takes_value(true)
                .value_names(&["REPORT"])
                .help(
                    "Path to save report. Path can be a directory, then report name is generated",
                ),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .help("Print CASR report to stdout"),
        )
        .group(
            ArgGroup::new("out")
                .args(&["stdout", "output"])
                .required(true),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .takes_value(true)
                .value_name("FILE")
                .help("Stdin file for program"),
        )
        .arg(
            Arg::new("ARGS")
                .multiple_values(true)
                .takes_value(true)
                .last(true)
                .help("Add \"-- ./binary <arguments>\" to run executable"),
        )
        .get_matches();

    // Get program args.
    let argv: Vec<&str> = if let Some(argvs) = matches.values_of("ARGS") {
        argvs.collect()
    } else {
        bail!("Wrong arguments for starting program");
    };

    // Get stdin for target program.
    let stdin_file = if let Some(path) = matches.value_of("stdin") {
        let file = PathBuf::from(path);
        if file.exists() {
            Some(file)
        } else {
            bail!("Stdin file not found: {}", file.display());
        }
    } else {
        None
    };

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
        header::EM_386 | header::EM_ARM | header::EM_X86_64 => machine.arch = elf_h.e_machine,
        _ => {
            bail!("Unsupported architecture: {}", elf_h.e_machine);
        }
    }

    let result = GdbCommand::new(&ExecType::Local(argv.as_slice()))
        .stdin(&stdin_file)
        .r()
        .bt()
        .siginfo()
        .mappings()
        .regs()
        .launch()?;

    report.stacktrace = result[0].split('\n').map(|x| x.to_string()).collect();
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

    let context = CrashContext {
        siginfo: siginfo.unwrap(),
        mappings: MappedFiles::from_gdb(&result[2])?,
        registers: Registers::from_gdb(&result[3])?,
        machine,
    };

    let result = analysis::severity(&mut report, &context)?;

    report.execution_class = result.clone();
    report.registers = context.registers;

    // Get crash line.
    if let Ok(crash_line) = debug::crash_line(&report) {
        report.crashline = crash_line.to_string();
        if let CrashLine::Source(debug) = crash_line {
            if let Some(sources) = debug::sources(&debug) {
                report.source = sources;
            }
        }
    }

    if matches.is_present("output") {
        let result_path = PathBuf::from(matches.value_of("output").unwrap());
        let mut file = File::create(&result_path)
            .with_context(|| format!("Couldn't create report: {}", result_path.display()))?;
        file.write_all(serde_json::to_string_pretty(&report).unwrap().as_bytes())
            .with_context(|| format!("Couldn't write report: {}", result_path.display()))?;
    }

    if matches.is_present("stdout") {
        println!("{}\n", serde_json::to_string_pretty(&report).unwrap());
    }
    Ok(())
}
