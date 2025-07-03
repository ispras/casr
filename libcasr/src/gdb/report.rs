//! Gdb module implements `ParseStacktrace`, `Exception` and `Severity` traits for Gdb output.
use std::collections::HashMap;

use gdb_command::{
    GdbCommand,
    mappings::{MappedFiles, MappedFilesExt},
    memory::MemoryObject,
    registers::{Registers, RegistersExt},
    siginfo::Siginfo,
    stacktrace::StacktraceExt,
};
use regex::Regex;

use crate::{
    error::{Error, Result},
    execution_class::ExecutionClass,
    gdb::{
        GdbStacktrace,
        exploitable::{GdbContext, MachineInfo},
    },
    report::ReportExtractor,
    severity::Severity,
    stacktrace::{CrashLine, CrashLineExt, ParseStacktrace, Stacktrace},
};

/// Structure provides an interface for save parsing gdb crash.
pub struct GdbCrash {
    context: GdbContext,
    maps: Vec<String>,
    report: Vec<String>,
    stream: String,
    stacktrace: Option<Stacktrace>,
}

impl GdbCrash {
    /// Create new `GdbCrash` instance from GdbCommand and MachineInfo.
    pub fn new(cmd: &mut GdbCommand, machine: MachineInfo) -> Result<Self> {
        // Get output
        let Ok(stream) = cmd.raw() else {
            return Err(Error::Casr("Unable to get results from gdb".to_string()));
        };
        let stream = String::from_utf8_lossy(&stream);
        let stream = stream.to_string();
        let report = cmd.parse(&stream)?;
        // Create GdbContext
        let stacktrace = GdbStacktrace::extract_stacktrace(&report[0])?;
        let siginfo = Siginfo::from_gdb(&report[1]);
        if let Err(error) = siginfo {
            let err_str = error.to_string();
            let re = Regex::new(r"\$\d+ = (0x0|void) doesn't match regex template").unwrap();
            if err_str.contains(":  doesn't match") || re.is_match(&err_str) {
                // Normal termination.
                return Err(Error::Casr("Program terminated (no crash)".to_string()));
            } else {
                return Err(error.into());
            }
        }
        let context = GdbContext {
            siginfo: siginfo.unwrap(),
            mappings: MappedFiles::from_gdb(&report[2])?,
            registers: Registers::from_gdb(&report[3])?,
            pc_memory: MemoryObject::from_gdb(&report[4])?,
            machine,
            stacktrace,
        };
        let maps = report[2]
            .split('\n')
            .skip(3)
            .map(|x| x.to_string())
            .collect();

        Ok(Self {
            context,
            maps,
            report,
            stream,
            stacktrace: None,
        })
    }
    /// Get disassembly
    pub fn disassembly(&self) -> &str {
        &self.report[5]
    }
    /// Get proc map.
    pub fn proc_maps(&self) -> &Vec<String> {
        &self.maps
    }
    /// Get registers
    pub fn registers(&self) -> &HashMap<String, u64> {
        &self.context.registers
    }
}

impl ReportExtractor for GdbCrash {
    fn extract_stacktrace(&mut self) -> Result<Vec<String>> {
        Ok(self.context.stacktrace.clone())
    }
    fn parse_stacktrace(&mut self) -> Result<Stacktrace> {
        if let Some(stacktrace) = &self.stacktrace {
            Ok(stacktrace.to_vec())
        } else {
            let mut stacktrace = GdbStacktrace::parse_stacktrace(&self.context.stacktrace)?;
            if let Ok(mfiles) = MappedFiles::from_gdb(self.proc_maps().join("\n")) {
                stacktrace.compute_module_offsets(&mfiles);
            }
            self.stacktrace = Some(stacktrace.clone());
            Ok(stacktrace)
        }
    }
    fn crash_line(&mut self) -> Result<CrashLine> {
        self.parse_stacktrace()?.crash_line()
    }
    fn stream(&self) -> &str {
        &self.stream
    }
    fn report(&self) -> Vec<String> {
        self.report.clone()
    }
    fn execution_class(&self) -> Result<ExecutionClass> {
        self.context.severity()
    }
}
