use crate::{common, common::Mode, util};
use libcasr::{
    gdb::{GdbCrash, exploitable::MachineInfo},
    report::{CrashReport, ReportExtractor},
};

use std::fs::File;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
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
