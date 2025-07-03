use std::{fs::File, io::Read, path::PathBuf};

use anyhow::{Context, Result, bail};
use gdb_command::{ExecType, GdbCommand};
use goblin::{
    container::Endian,
    elf::{Elf, header},
};

use libcasr::{
    gdb::{exploitable::MachineInfo, report::GdbCrash},
    report::{CrashReport, ReportExtractor},
};

use crate::{mode::DynMode, util};

use super::Runner;

// TODO: Docs
pub struct GdbRunner {}

impl Runner for GdbRunner {
    fn run(
        &self,
        _mode: &mut DynMode,
        argv: &[String],
        stdin: &Option<PathBuf>,
        timeout: u64,
        _ld_preload: &Option<String>, // TODO: Add support
    ) -> Result<Option<(CrashReport, Box<dyn ReportExtractor>)>> {
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
        let mut report = util::get_report_stub(argv, stdin);

        // Fill extra report fields
        report.proc_maps = extractor.proc_maps().to_vec();
        report.registers = extractor.registers().clone();
        report.set_disassembly(extractor.disassembly());

        Ok(Some((report, Box::new(extractor))))
    }
}
