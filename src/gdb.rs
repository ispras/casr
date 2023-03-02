extern crate capstone;

use std::collections::HashSet;

use capstone::arch::arm::ArmInsn;
use capstone::arch::x86::X86Insn;
use capstone::arch::*;
use capstone::prelude::*;
use capstone::{Insn, InsnId, Instructions};
use gdb_command::mappings::*;
use gdb_command::memory::*;
use gdb_command::registers::*;
use gdb_command::siginfo::*;
use gdb_command::stacktrace::*;
use goblin::container::Endian;
use goblin::elf::header;
use regex::Regex;

use super::error::*;
use super::execution_class::ExecutionClass;
use super::severity::Severity;
use super::stacktrace::*;

#[derive(Clone, Default)]
/// Information about machine.
pub struct MachineInfo {
    // x86, x86_64, arm32
    pub arch: u16,
    // Little, Big
    pub endianness: Endian,
    // 4 or 8 bytes
    pub byte_width: u8,
}

#[derive(Clone, Default)]
/// Information about crash state.
pub struct GdbContext {
    pub siginfo: Siginfo,
    pub registers: Registers,
    pub mappings: MappedFiles,
    pub machine: MachineInfo,
    pub pc_memory: MemoryObject,
    pub stacktrace: Vec<String>,
}

/// Structure provides an interface for processing the stack trace.
pub struct GdbStacktrace;

impl ParseStacktrace for GdbStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let frame = Regex::new(r"^ *#[0-9]+").unwrap();
        Ok(stream
            .split('\n')
            .filter(|x| frame.is_match(x))
            .map(|x| x.to_string())
            .collect())
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        Ok(Stacktrace::from_gdb(entries.join("\n"))?)
    }
}

impl Severity for GdbContext {
    fn severity(&self) -> Result<ExecutionClass> {
        // Check signal number.
        match self.siginfo.si_signo {
            SIGINFO_SIGABRT => {
                if self.stacktrace.iter().any(|entry| entry.contains("cfree")) {
                    return ExecutionClass::find("HeapError");
                }
                if self
                    .stacktrace
                    .iter()
                    .any(|entry| entry.contains("__chk_fail"))
                {
                    return ExecutionClass::find("SafeFunctionCheck");
                }
                if self
                    .stacktrace
                    .iter()
                    .any(|entry| entry.contains("_stack_chk_fail"))
                {
                    return ExecutionClass::find("StackGuard");
                }

                ExecutionClass::find("AbortSignal")
            }
            SIGINFO_SIGTRAP => ExecutionClass::find("TrapSignal"),
            SIGINFO_SIGILL | SIGINFO_SIGSYS => ExecutionClass::find("BadInstruction"),
            SIGINFO_SIGSEGV | SIGINFO_SIGFPE | SIGINFO_SIGBUS => {
                // Get program counter.
                let pc = self.pc();

                if pc.is_none() {
                    return Err(Error::Casr("Unable to get Program counter.".to_string()));
                }

                let pc = pc.unwrap();

                // Check for segfaultOnPC.
                if self.siginfo.si_signo == SIGINFO_SIGSEGV && *pc == self.siginfo.si_addr {
                    if is_near_null(self.siginfo.si_addr) {
                        return ExecutionClass::find("SegFaultOnPcNearNull");
                    } else {
                        return ExecutionClass::find("SegFaultOnPc");
                    };
                }
                if self.siginfo.si_signo == SIGINFO_SIGSEGV
                    && self.pc_memory.data.is_empty()
                    && self.siginfo.si_code == SI_KERNEL
                {
                    return ExecutionClass::find("SegFaultOnPc");
                }

                // Initialize disassembler.
                let cs = match self.machine.arch {
                    header::EM_386 => Capstone::new()
                        .x86()
                        .mode(arch::x86::ArchMode::Mode32)
                        .syntax(arch::x86::ArchSyntax::Intel)
                        .detail(true)
                        .build(),
                    header::EM_X86_64 => Capstone::new()
                        .x86()
                        .mode(arch::x86::ArchMode::Mode64)
                        .syntax(arch::x86::ArchSyntax::Intel)
                        .detail(true)
                        .build(),
                    header::EM_ARM => {
                        if let Some(cpsr) = self.registers.get("cpsr") {
                            Capstone::new()
                                .arm()
                                .mode(if *cpsr & 0x20 != 0 {
                                    arch::arm::ArchMode::Thumb
                                } else {
                                    arch::arm::ArchMode::Arm
                                })
                                .detail(true)
                                .endian(if self.machine.endianness == Endian::Little {
                                    capstone::Endian::Little
                                } else {
                                    capstone::Endian::Big
                                })
                                .build()
                        } else {
                            return Err(Error::Casr(
                                "Unable to initialize disassembler for EM_ARM".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(Error::Casr(format!(
                            "Unsupported machine architecture: {}",
                            self.machine.arch
                        )))
                    }
                };

                if let Ok(cs) = cs {
                    // Get disassembly for report.
                    let insns = cs.disasm_all(&self.pc_memory.data, *pc);
                    if let Ok(insns) = insns {
                        let mut disassembly = Vec::new();
                        insns
                            .iter()
                            .for_each(|i| disassembly.push(format!("    {i}")));
                        if let Some(insn) = disassembly.get(0) {
                            let new_insn = format!("==> {}", insn.trim_start());
                            let _ = std::mem::replace(&mut disassembly[0], new_insn);
                        }
                        disassembly.truncate(16);

                        if self.siginfo.si_signo == SIGINFO_SIGSEGV
                            || self.siginfo.si_signo == SIGINFO_SIGBUS
                        {
                            Self::analyze_instructions(&cs, &insns, self)
                        } else {
                            ExecutionClass::find("FPE")
                        }
                    } else {
                        Err(Error::Casr(
                            "Unable to get Capstone Instructions.".to_string(),
                        ))
                    }
                } else {
                    Err(Error::Casr(format!(
                        "Unable to initialize architecture disassembler: {}",
                        self.machine.arch
                    )))
                }
            }
            _ => Err(Error::Casr(format!(
                "Unsupported signal :{}",
                self.siginfo.si_signo
            ))),
        }
    }
}

/// Check if value is near null (less than 64*1024).
///
///  # Arguments
///
/// * `value` -  address value to check.
pub fn is_near_null(value: u64) -> bool {
    value < 64 * 1024
}

impl GdbContext {
    /// Get stack pointer value for current architecture.
    pub fn sp(&self) -> Option<&u64> {
        match self.machine.arch {
            header::EM_X86_64 => self.registers.get("rsp"),
            header::EM_386 => self.registers.get("esp"),
            header::EM_ARM => self.registers.get("sp"),
            _ => None,
        }
    }

    /// Get program counter.
    pub fn pc(&self) -> Option<&u64> {
        match self.machine.arch {
            header::EM_386 => self.registers.get("eip"),
            header::EM_X86_64 => self.registers.get("rip"),
            header::EM_ARM => self.registers.get("pc"),
            _ => None,
        }
    }

    /// Analyze crash instruction and return ExecutionClass or error.
    ///
    /// # Arguments
    ///
    /// * `cs` - reference to capstone disassembler.
    ///
    /// * `insns` - reference to disassembled instructions.
    ///
    /// * `context` - crash context.
    fn analyze_instructions(
        cs: &Capstone,
        insns: &Instructions,
        context: &GdbContext,
    ) -> Result<ExecutionClass> {
        match context.machine.arch {
            header::EM_386 | header::EM_X86_64 => {
                Self::analyze_instructions_x86(cs, insns, context)
            }
            header::EM_ARM => Self::analyze_instructions_arm(cs, insns, &context.siginfo),
            _ => Err(Error::Casr(format!(
                "Unsupported machine arch: {}",
                context.machine.arch
            ))),
        }
    }

    /// Analyze x86 crash instruction.
    ///
    /// # Arguments
    ///
    /// * `cs` - reference to capstone.
    ///
    /// * `insns` - reference to disassembled instructions.
    ///
    /// * `context` - crash context.
    fn analyze_instructions_x86(
        cs: &Capstone,
        insns: &Instructions,
        context: &GdbContext,
    ) -> Result<ExecutionClass> {
        // Get first instruction.
        let Some(insn) = insns.iter().next() else {
            return Err(Error::Casr(
                "Couldn't get first x86 instruction".to_string(),
            ));
        };

        let Ok(detail) = cs.insn_detail(&insn) else {
            return Err(Error::Casr(
                "Couldn't capstone instruction details".to_string(),
            ));
        };

        // Check for return.
        if detail.groups().any(|x| cs.group_name(x).unwrap() == "ret") {
            return ExecutionClass::find("ReturnAv");
        }
        // Check for call.
        if detail.groups().any(|x| cs.group_name(x).unwrap() == "call") {
            // Check for exceeded stack.
            if let Some(sp) = context.sp() {
                if (*sp - context.machine.byte_width as u64) == context.siginfo.si_addr {
                    return ExecutionClass::find("StackOverflow");
                }
            }
            // Check for Call reg, Call [reg].
            if detail.regs_read_count() > 0 {
                if !is_near_null(context.siginfo.si_addr) || context.siginfo.si_code == SI_KERNEL {
                    return ExecutionClass::find("CallAv");
                } else {
                    return ExecutionClass::find("CallAvNearNull");
                }
            }
        }
        // Check for jump.
        if detail.groups().any(|x| cs.group_name(x).unwrap() == "jump") {
            // Check for Jump reg, Jump [reg].
            if detail.regs_read_count() > 0 {
                if !is_near_null(context.siginfo.si_addr) || context.siginfo.si_code == SI_KERNEL {
                    return ExecutionClass::find("BranchAv");
                } else {
                    return ExecutionClass::find("BranchAvNearNull");
                }
            }
        }

        // Check for mov instructions.
        let mnemonic = insn.mnemonic();
        if mnemonic.is_none() {
            return Err(Error::Casr(
                "Couldn't capstone instruction mnemonic".to_string(),
            ));
        }
        let mnemonic = mnemonic.unwrap();
        if mnemonic.to_string().contains("mov") {
            // Get operands.
            let ops = detail.arch_detail().operands();
            for (num, op) in ops.iter().enumerate() {
                // Safe.
                let operand = if let capstone::arch::ArchOperand::X86Operand(operand) = op {
                    operand
                } else {
                    return Err(Error::Casr(
                        "Couldn't capstone instruction operands".to_string(),
                    ));
                };

                // Check mem operand.
                if let capstone::arch::x86::X86OperandType::Mem(_) = operand.op_type {
                    match (
                        context.siginfo.si_signo,
                        context.siginfo.si_code,
                        num,
                        is_near_null(context.siginfo.si_addr),
                    ) {
                        (SIGINFO_SIGBUS, _, 1, _) => {
                            return ExecutionClass::find("SourceAv");
                        }
                        (_, SI_KERNEL, 0, _) | (_, _, 0, false) | (SIGINFO_SIGBUS, _, 0, _) => {
                            return ExecutionClass::find("DestAv");
                        }
                        (_, _, 0, true) => {
                            return ExecutionClass::find("DestAvNearNull");
                        }
                        (_, SI_KERNEL, 1, _) | (_, _, 1, false) => {
                            if let Ok(new_class) = check_taint(cs, insns) {
                                return Ok(new_class);
                            } else {
                                return ExecutionClass::find("SourceAv");
                            }
                        }
                        (_, _, 1, true) => return ExecutionClass::find("SourceAvNearNull"),
                        _ => return ExecutionClass::find("AccessViolation"),
                    }
                }
            }
        }
        ExecutionClass::find("AccessViolation")
    }

    /// Analyze arm crash instruction
    ///
    /// # Arguments
    ///
    /// * `cs` - reference to capstone.
    ///
    /// * `insns` - reference to disassembled instructions.
    ///
    /// * `info` - reference to signal information struct.
    fn analyze_instructions_arm(
        cs: &Capstone,
        insns: &Instructions,
        info: &Siginfo,
    ) -> Result<ExecutionClass> {
        // Get first instruction.
        let Some(insn) = insns.iter().next() else {
            return Err(Error::Casr(
                "Couldn't get first arm instruction".to_string(),
            ));
        };

        let Ok(detail) = cs.insn_detail(&insn) else {
            return Err(Error::Casr(
                "Couldn't capstone instruction details".to_string(),
            ));
        };

        // Check for mov instructions.
        let Some(mnemonic) = insn.mnemonic() else {
            return Err(Error::Casr(
                "Couldn't capstone instruction mnemonic".to_string(),
            ));
        };
        let m = mnemonic.to_string();

        let ops = detail.arch_detail().operands();
        for op in ops.iter() {
            // Safe.
            let capstone::arch::ArchOperand::ArmOperand(operand) = op else {
                return Err(Error::Casr(
                    "Couldn't capstone instruction operands".to_string(),
                ));
            };
            // Check mem operand.
            if let capstone::arch::arm::ArmOperandType::Mem(_) = operand.op_type {
                match (
                    info.si_code,
                    m.contains("str"),
                    m.contains("ldr"),
                    is_near_null(info.si_addr),
                ) {
                    (SI_KERNEL, true, false, _) | (_, true, false, false) => {
                        return ExecutionClass::find("DestAv")
                    }
                    (_, true, false, true) => return ExecutionClass::find("DestAvNearNull"),
                    (SI_KERNEL, false, true, _) | (_, false, true, false) => {
                        if let Ok(new_class) = check_taint(cs, insns) {
                            return Ok(new_class);
                        } else {
                            return ExecutionClass::find("SourceAv");
                        }
                    }
                    (_, false, true, true) => return ExecutionClass::find("SourceAvNearNull"),
                    _ => return ExecutionClass::find("AccessViolation"),
                };
            }
        }
        ExecutionClass::find("AccessViolation")
    }
}
// Signal numbers.
pub const SIGINFO_SIGILL: u32 = 4;
pub const SIGINFO_SIGTRAP: u32 = 5;
pub const SIGINFO_SIGABRT: u32 = 6;
pub const SIGINFO_SIGBUS: u32 = 7;
pub const SIGINFO_SIGFPE: u32 = 8;
pub const SIGINFO_SIGSEGV: u32 = 11;
pub const SIGINFO_SIGSYS: u32 = 31;

pub const SI_KERNEL: u32 = 0x80;

// The goal is to find taint registers in call/jump or in memory address for store instructions.
// Limitations: 1. Track only registers not memory cells.
//              2. Track only within current basic block.

/// Do taint analysis from first instruction from list to find new ExecutionClass.
/// Returns ExecutionClass if succeed.
/// # Arguments
///
/// * `cs` - capstone.
///
/// * `insns` - instruction list to analyze.
fn check_taint(cs: &Capstone, insns: &Instructions) -> Result<ExecutionClass> {
    let mut taint_set: HashSet<RegId> = HashSet::new();
    for (index, insn) in insns.iter().enumerate() {
        match process_instruction(cs, &insn, index, &mut taint_set) {
            InstructionType::ControlFlowTransfer | InstructionType::Unknown => break,
            InstructionType::TaintedCall => return ExecutionClass::find("CallAvTainted"),
            InstructionType::TaintedJMP => return ExecutionClass::find("BranchAvTainted"),
            InstructionType::TaintedRet => return ExecutionClass::find("ReturnAv"),
            InstructionType::TaintedMemStore => return ExecutionClass::find("DestAvTainted"),
            InstructionType::TaintedPc => return ExecutionClass::find("SegFaultOnPc"),
            _ => {}
        }
    }
    Err(Error::Casr(
        "Couldn't find new ExecutionClass using taint tracking".to_string(),
    ))
}

/// Process instruction and propagate taint data.
/// First instruction initializes taint set.
/// Return instruction type.
///
/// # Arguments
///
/// * `cs` - capstone.
///
/// * `insn` - instruction.
///
/// * `index` - index of instruction in list.
///
/// * `taint_set` - reference to taint watch set.
fn process_instruction(
    cs: &Capstone,
    insn: &Insn,
    index: usize,
    taint_set: &mut HashSet<RegId>,
) -> InstructionType {
    let detail = cs.insn_detail(insn);
    if detail.is_err() {
        return InstructionType::Unknown;
    }

    let detail = detail.unwrap();

    match detail.arch_detail() {
        ArchDetail::ArmDetail(arm_detail) => {
            match insn_type_arm(insn.id()) {
                InstructionType::ControlFlowTransfer => {
                    // Only BX, BLX with registers could lead to hijack.
                    if let Some(first_op) = arm_detail.operands().next() {
                        match first_op.op_type {
                            arm::ArmOperandType::Reg(t1) => {
                                if taint_set.contains(&t1) {
                                    InstructionType::TaintedJMP
                                } else {
                                    InstructionType::ControlFlowTransfer
                                }
                            }
                            _ => InstructionType::ControlFlowTransfer,
                        }
                    } else {
                        InstructionType::ControlFlowTransfer
                    }
                }
                InstructionType::Arithmetic => {
                    // Propagate registers.
                    let first_op: arm::ArmOperand = arm_detail.operands().next().unwrap();
                    let second_op: arm::ArmOperand = arm_detail.operands().nth(1).unwrap();
                    if let (arm::ArmOperandType::Reg(t1), arm::ArmOperandType::Reg(t2)) =
                        (first_op.op_type, second_op.op_type)
                    {
                        // Check shifter.
                        match second_op.shift {
                            arm::ArmShift::AsrReg(r)
                            | arm::ArmShift::LsrReg(r)
                            | arm::ArmShift::LslReg(r)
                            | arm::ArmShift::RorReg(r)
                            | arm::ArmShift::RrxReg(r) => {
                                if taint_set.contains(&r) {
                                    taint_set.insert(t2);
                                }
                            }
                            _ => {}
                        }
                        // Propagate t2 -> t1.
                        if taint_set.contains(&t2) {
                            taint_set.insert(t1);
                        }
                    }
                    InstructionType::Arithmetic
                }
                InstructionType::DataTransfer => {
                    let mut t = InstructionType::DataTransfer;
                    match insn.id() {
                        ARM_INS_MOV => {
                            // Propagate, check pc
                            let first_op: arm::ArmOperand = arm_detail.operands().next().unwrap();
                            let second_op: arm::ArmOperand = arm_detail.operands().nth(1).unwrap();
                            match (first_op.op_type, second_op.op_type) {
                                (arm::ArmOperandType::Reg(t1), arm::ArmOperandType::Reg(t2)) => {
                                    // Check shifter.
                                    match second_op.shift {
                                        arm::ArmShift::AsrReg(r)
                                        | arm::ArmShift::LsrReg(r)
                                        | arm::ArmShift::LslReg(r)
                                        | arm::ArmShift::RorReg(r)
                                        | arm::ArmShift::RrxReg(r) => {
                                            if taint_set.contains(&r) {
                                                taint_set.insert(t2);
                                            }
                                        }
                                        _ => {}
                                    }
                                    // Propagate t2 -> t1
                                    if taint_set.contains(&t2) {
                                        taint_set.insert(t1);
                                    }
                                    if t1 == RegId(11) {
                                        t = if taint_set.contains(&t1) {
                                            InstructionType::TaintedPc
                                        } else {
                                            InstructionType::ControlFlowTransfer
                                        };
                                    }
                                }
                                (arm::ArmOperandType::Reg(t1), arm::ArmOperandType::Imm(_)) => {
                                    if taint_set.contains(&t1) {
                                        taint_set.remove(&t1);
                                    }
                                }
                                _ => {}
                            }
                        }
                        ARM_INS_LDR => {
                            let first_op: arm::ArmOperand = arm_detail.operands().next().unwrap();
                            let second_op: arm::ArmOperand = arm_detail.operands().nth(1).unwrap();
                            if let (arm::ArmOperandType::Reg(t1), arm::ArmOperandType::Mem(t2)) =
                                (first_op.op_type, second_op.op_type)
                            {
                                // Read data from memory. If address is tainted, then value is tainted.
                                // If this is a first instruction in list, value is tainted.
                                if taint_set.contains(&t2.base())
                                    || taint_set.contains(&t2.index())
                                    || index == 0
                                {
                                    taint_set.insert(t1);
                                    // Ldr to PC.
                                    if t1 == RegId(11) {
                                        t = InstructionType::TaintedPc;
                                    }
                                } else {
                                    taint_set.remove(&t1);
                                }
                            }
                        }
                        ARM_INS_STR => {
                            let first_op: arm::ArmOperand = arm_detail.operands().next().unwrap();
                            let second_op: arm::ArmOperand = arm_detail.operands().nth(1).unwrap();
                            if let (arm::ArmOperandType::Reg(_), arm::ArmOperandType::Mem(t1)) =
                                (first_op.op_type, second_op.op_type)
                            {
                                if taint_set.contains(&t1.base()) || taint_set.contains(&t1.index())
                                {
                                    t = InstructionType::TaintedMemStore;
                                }
                            }
                        }
                        _ => {}
                    }
                    t
                }
                InstructionType::BinaryCMP => {
                    // Do nothing cmps do not propagate values.
                    InstructionType::BinaryCMP
                }
                InstructionType::Unary => InstructionType::Unary,
                _ => InstructionType::Unknown,
            }
        }
        ArchDetail::X86Detail(x86_detail) => {
            match insn_type_x86(insn.id()) {
                InstructionType::ControlFlowTransfer => {
                    if insn.id() == X86_INS_RET {
                        // Check if stack pointer is tainted.
                        if taint_set.contains(&RegId(30)) || taint_set.contains(&RegId(44)) {
                            InstructionType::TaintedRet
                        } else {
                            InstructionType::ControlFlowTransfer
                        }
                    } else if insn.id() == X86_INS_JMP || insn.id() == X86_INS_CALL {
                        let first_op: x86::X86Operand = x86_detail.operands().next().unwrap();
                        match first_op.op_type {
                            x86::X86OperandType::Reg(t1) => {
                                if taint_set.contains(&t1) {
                                    if insn.id() == X86_INS_JMP {
                                        InstructionType::TaintedJMP
                                    } else {
                                        InstructionType::TaintedCall
                                    }
                                } else {
                                    InstructionType::ControlFlowTransfer
                                }
                            }
                            x86::X86OperandType::Mem(t1) => {
                                if taint_set.contains(&t1.base()) || taint_set.contains(&t1.index())
                                {
                                    if insn.id() == X86_INS_JMP {
                                        InstructionType::TaintedJMP
                                    } else {
                                        InstructionType::TaintedCall
                                    }
                                } else {
                                    InstructionType::ControlFlowTransfer
                                }
                            }
                            _ => InstructionType::ControlFlowTransfer,
                        }
                    } else {
                        InstructionType::ControlFlowTransfer
                    }
                }
                InstructionType::DataTransfer => {
                    let mut t = InstructionType::DataTransfer;
                    // Get 1st and 2nd operand.
                    let first_op: x86::X86Operand = x86_detail.operands().next().unwrap();
                    let second_op: x86::X86Operand = x86_detail.operands().nth(1).unwrap();
                    match insn.id() {
                        X86_INS_MOV => {
                            match (first_op.op_type, second_op.op_type) {
                                (x86::X86OperandType::Reg(t1), x86::X86OperandType::Reg(t2)) => {
                                    // Propagate t2 -> t1.
                                    if taint_set.contains(&t2) {
                                        taint_set.insert(t1);
                                    }
                                }
                                (x86::X86OperandType::Reg(t1), x86::X86OperandType::Imm(_)) => {
                                    // Kill tainted value.
                                    if taint_set.contains(&t1) {
                                        taint_set.remove(&t1);
                                    }
                                }
                                (x86::X86OperandType::Reg(t1), x86::X86OperandType::Mem(t2)) => {
                                    // Read data from memory. If address is tainted, then value is tainted.
                                    // If this is a first instruction in list, value is tainted.
                                    if taint_set.contains(&t2.base())
                                        || taint_set.contains(&t2.index())
                                        || index == 0
                                    {
                                        taint_set.insert(t1);
                                    } else {
                                        taint_set.remove(&t1);
                                    }
                                }
                                (x86::X86OperandType::Mem(t1), x86::X86OperandType::Reg(_)) => {
                                    // Write data to memory.
                                    if taint_set.contains(&t1.base())
                                        || taint_set.contains(&t1.index())
                                    {
                                        t = InstructionType::TaintedMemStore;
                                    }
                                }
                                _ => {
                                    // Do nothing. Suppose memory always untainted.
                                }
                            }
                        }
                        X86_INS_XCHG => {
                            let first_op: x86::X86Operand = x86_detail.operands().next().unwrap();
                            let second_op: x86::X86Operand = x86_detail.operands().nth(1).unwrap();
                            match (first_op.op_type, second_op.op_type) {
                                (x86::X86OperandType::Reg(t1), x86::X86OperandType::Reg(t2)) => {
                                    if taint_set.contains(&t1) && !taint_set.contains(&t2) {
                                        taint_set.insert(t2);
                                        taint_set.remove(&t1);
                                    }
                                    if !taint_set.contains(&t1) && taint_set.contains(&t2) {
                                        taint_set.insert(t1);
                                        taint_set.remove(&t2);
                                    }
                                }
                                (x86::X86OperandType::Reg(t1), x86::X86OperandType::Mem(_)) => {
                                    taint_set.remove(&t1);
                                }
                                (x86::X86OperandType::Mem(_), x86::X86OperandType::Reg(t2)) => {
                                    taint_set.remove(&t2);
                                }
                                _ => {}
                            }
                        }
                        X86_INS_LEA => {
                            let first_op: x86::X86Operand = x86_detail.operands().next().unwrap();
                            let second_op: x86::X86Operand = x86_detail.operands().nth(1).unwrap();
                            if let (x86::X86OperandType::Reg(t1), x86::X86OperandType::Mem(t2)) =
                                (first_op.op_type, second_op.op_type)
                            {
                                if taint_set.contains(&t2.base()) || taint_set.contains(&t2.index())
                                {
                                    taint_set.insert(t1);
                                } else {
                                    taint_set.remove(&t1);
                                }
                            }
                        }
                        X86_INS_MOVZX | X86_INS_MOVSX => {
                            // Always kill.
                            let first_op: x86::X86Operand = x86_detail.operands().next().unwrap();
                            if let x86::X86OperandType::Reg(t1) = first_op.op_type {
                                taint_set.remove(&t1);
                            }
                        }
                        _ => {}
                    }
                    t
                }
                InstructionType::BinaryCMP => {
                    // Do nothing cmps do not propagate values.
                    InstructionType::BinaryCMP
                }
                InstructionType::Unary => {
                    // POP clears register if it is tainted.
                    if insn.id() == X86_INS_POP {
                        let first_op: x86::X86Operand = x86_detail.operands().next().unwrap();
                        if let x86::X86OperandType::Reg(t1) = first_op.op_type {
                            taint_set.remove(&t1);
                        }
                    }
                    InstructionType::Unary
                }
                InstructionType::Arithmetic => {
                    // Get 1st and 2nd operand.
                    let first_op: x86::X86Operand = x86_detail.operands().next().unwrap();
                    let second_op: x86::X86Operand = x86_detail.operands().nth(1).unwrap();
                    // Suppose memory always untainted. Track only registers.
                    if let (x86::X86OperandType::Reg(t1), x86::X86OperandType::Reg(t2)) =
                        (first_op.op_type, second_op.op_type)
                    {
                        // Propagate t2 -> t1.
                        if taint_set.contains(&t2) {
                            taint_set.insert(t1);
                        }
                    }
                    InstructionType::Arithmetic
                }
                _ => InstructionType::Unknown,
            }
        }
        _ => InstructionType::Unknown,
    }
}

/// Return Instruction type by Id for x86 instruction.
///
/// # Arguments
///
/// * `id` - mnemonic id.
fn insn_type_x86(id: InsnId) -> InstructionType {
    match id {
        X86_INS_CALL | X86_INS_RET | X86_INS_JMP | X86_INS_JA | X86_INS_JAE | X86_INS_JBE
        | X86_INS_JB | X86_INS_JCXZ | X86_INS_JECXZ | X86_INS_JE | X86_INS_JGE | X86_INS_JG
        | X86_INS_JLE | X86_INS_JL | X86_INS_JNE | X86_INS_JNO | X86_INS_JNP | X86_INS_JNS
        | X86_INS_JO | X86_INS_JP | X86_INS_JRCXZ | X86_INS_JS => {
            InstructionType::ControlFlowTransfer
        }
        X86_INS_OR | X86_INS_SUB | X86_INS_XOR | X86_INS_ROL | X86_INS_ROR | X86_INS_SAL
        | X86_INS_SAR | X86_INS_SHL | X86_INS_SHR | X86_INS_ADD | X86_INS_AND => {
            InstructionType::Arithmetic
        }
        X86_INS_MOV | X86_INS_XCHG | X86_INS_LEA | X86_INS_MOVZX | X86_INS_MOVSX => {
            InstructionType::DataTransfer
        }
        X86_INS_NEG | X86_INS_NOT | X86_INS_POP | X86_INS_DEC | X86_INS_INC => {
            InstructionType::Unary
        }
        X86_INS_TEST | X86_INS_CMP => InstructionType::BinaryCMP,
        _ => InstructionType::Unknown,
    }
}

/// Return Instruction type by Id for arm instruction.
///
/// # Arguments
///
/// * `id` - mnemonic id
fn insn_type_arm(id: InsnId) -> InstructionType {
    match id {
        ARM_INS_B | ARM_INS_BL | ARM_INS_CBZ | ARM_INS_CBNZ | ARM_INS_BX | ARM_INS_BLX => {
            InstructionType::ControlFlowTransfer
        }
        ARM_INS_ADC | ARM_INS_ADD | ARM_INS_ADDW | ARM_INS_AND | ARM_INS_EOR | ARM_INS_LSL
        | ARM_INS_LSR | ARM_INS_ASR | ARM_INS_ORN | ARM_INS_ROR | ARM_INS_RRX | ARM_INS_SUBW
        | ARM_INS_SUB | ARM_INS_RSB | ARM_INS_ORR | ARM_INS_MUL | ARM_INS_SDIV => {
            InstructionType::Arithmetic
        }
        ARM_INS_STR | ARM_INS_LDR | ARM_INS_MOV => InstructionType::DataTransfer,
        ARM_INS_REV | ARM_INS_RBIT => InstructionType::Unary,
        ARM_INS_CMP | ARM_INS_TST | ARM_INS_TEQ => InstructionType::BinaryCMP,
        _ => InstructionType::Unknown,
    }
}

/// Instruction types for taint propagation.
enum InstructionType {
    Unknown,
    ControlFlowTransfer,
    DataTransfer,
    Arithmetic,
    Unary,
    BinaryCMP,
    TaintedCall,
    TaintedJMP,
    TaintedRet,
    TaintedMemStore,
    TaintedPc,
}

// Arm 32bit mnemonic iDs.
// ControlTransfer
const ARM_INS_B: InsnId = InsnId(ArmInsn::ARM_INS_B as u32);
const ARM_INS_BL: InsnId = InsnId(ArmInsn::ARM_INS_BL as u32);
const ARM_INS_CBZ: InsnId = InsnId(ArmInsn::ARM_INS_CBZ as u32);
const ARM_INS_CBNZ: InsnId = InsnId(ArmInsn::ARM_INS_CBNZ as u32);

// PossibleTaint, ControlTransfer
const ARM_INS_BX: InsnId = InsnId(ArmInsn::ARM_INS_BX as u32);
const ARM_INS_BLX: InsnId = InsnId(ArmInsn::ARM_INS_BLX as u32);

// Arithmetic.
const ARM_INS_ADC: InsnId = InsnId(ArmInsn::ARM_INS_ADC as u32);
const ARM_INS_ADD: InsnId = InsnId(ArmInsn::ARM_INS_ADD as u32);
const ARM_INS_ADDW: InsnId = InsnId(ArmInsn::ARM_INS_ADDW as u32);
const ARM_INS_AND: InsnId = InsnId(ArmInsn::ARM_INS_AND as u32);
const ARM_INS_EOR: InsnId = InsnId(ArmInsn::ARM_INS_EOR as u32);
const ARM_INS_LSL: InsnId = InsnId(ArmInsn::ARM_INS_LSL as u32);
const ARM_INS_LSR: InsnId = InsnId(ArmInsn::ARM_INS_LSR as u32);
const ARM_INS_ASR: InsnId = InsnId(ArmInsn::ARM_INS_ASR as u32);
const ARM_INS_ORN: InsnId = InsnId(ArmInsn::ARM_INS_ORN as u32);
const ARM_INS_ROR: InsnId = InsnId(ArmInsn::ARM_INS_ROR as u32);
const ARM_INS_RRX: InsnId = InsnId(ArmInsn::ARM_INS_RRX as u32);
const ARM_INS_SUBW: InsnId = InsnId(ArmInsn::ARM_INS_SUBW as u32);
const ARM_INS_SUB: InsnId = InsnId(ArmInsn::ARM_INS_SUB as u32);
const ARM_INS_RSB: InsnId = InsnId(ArmInsn::ARM_INS_RSB as u32);
const ARM_INS_ORR: InsnId = InsnId(ArmInsn::ARM_INS_ORR as u32);
const ARM_INS_MUL: InsnId = InsnId(ArmInsn::ARM_INS_MUL as u32);
const ARM_INS_SDIV: InsnId = InsnId(ArmInsn::ARM_INS_SDIV as u32);

// PossibleTaint, DataTransfer.
const ARM_INS_STR: InsnId = InsnId(ArmInsn::ARM_INS_STR as u32);

// DataTransfer.
const ARM_INS_LDR: InsnId = InsnId(ArmInsn::ARM_INS_LDR as u32);
const ARM_INS_MOV: InsnId = InsnId(ArmInsn::ARM_INS_MOV as u32);

// Unary.
const ARM_INS_REV: InsnId = InsnId(ArmInsn::ARM_INS_REV as u32);
const ARM_INS_RBIT: InsnId = InsnId(ArmInsn::ARM_INS_RBIT as u32);
// BinaryCMP.
const ARM_INS_CMP: InsnId = InsnId(ArmInsn::ARM_INS_CMP as u32);
const ARM_INS_TST: InsnId = InsnId(ArmInsn::ARM_INS_TST as u32);
const ARM_INS_TEQ: InsnId = InsnId(ArmInsn::ARM_INS_TEQ as u32);

// x86 mnemonic iDs.
// PossibleTaint, ControlTransfer.
const X86_INS_CALL: InsnId = InsnId(X86Insn::X86_INS_CALL as u32);
const X86_INS_RET: InsnId = InsnId(X86Insn::X86_INS_RET as u32);
const X86_INS_JMP: InsnId = InsnId(X86Insn::X86_INS_JMP as u32);

// ControlTransfer.
const X86_INS_JAE: InsnId = InsnId(X86Insn::X86_INS_JAE as u32);
const X86_INS_JA: InsnId = InsnId(X86Insn::X86_INS_JA as u32);
const X86_INS_JBE: InsnId = InsnId(X86Insn::X86_INS_JBE as u32);
const X86_INS_JB: InsnId = InsnId(X86Insn::X86_INS_JB as u32);
const X86_INS_JCXZ: InsnId = InsnId(X86Insn::X86_INS_JCXZ as u32);
const X86_INS_JECXZ: InsnId = InsnId(X86Insn::X86_INS_JECXZ as u32);
const X86_INS_JE: InsnId = InsnId(X86Insn::X86_INS_JE as u32);
const X86_INS_JGE: InsnId = InsnId(X86Insn::X86_INS_JGE as u32);
const X86_INS_JG: InsnId = InsnId(X86Insn::X86_INS_JG as u32);
const X86_INS_JLE: InsnId = InsnId(X86Insn::X86_INS_JLE as u32);
const X86_INS_JL: InsnId = InsnId(X86Insn::X86_INS_JL as u32);
const X86_INS_JNE: InsnId = InsnId(X86Insn::X86_INS_JNE as u32);
const X86_INS_JNO: InsnId = InsnId(X86Insn::X86_INS_JNO as u32);
const X86_INS_JNP: InsnId = InsnId(X86Insn::X86_INS_JNP as u32);
const X86_INS_JNS: InsnId = InsnId(X86Insn::X86_INS_JNS as u32);
const X86_INS_JO: InsnId = InsnId(X86Insn::X86_INS_JO as u32);
const X86_INS_JP: InsnId = InsnId(X86Insn::X86_INS_JP as u32);
const X86_INS_JRCXZ: InsnId = InsnId(X86Insn::X86_INS_JRCXZ as u32);
const X86_INS_JS: InsnId = InsnId(X86Insn::X86_INS_JS as u32);

// Arithmetic.
const X86_INS_OR: InsnId = InsnId(X86Insn::X86_INS_OR as u32);
const X86_INS_SUB: InsnId = InsnId(X86Insn::X86_INS_SUB as u32);
const X86_INS_XOR: InsnId = InsnId(X86Insn::X86_INS_XOR as u32);
const X86_INS_ROL: InsnId = InsnId(X86Insn::X86_INS_ROL as u32);
const X86_INS_ROR: InsnId = InsnId(X86Insn::X86_INS_ROR as u32);
const X86_INS_SAL: InsnId = InsnId(X86Insn::X86_INS_SAL as u32);
const X86_INS_SAR: InsnId = InsnId(X86Insn::X86_INS_SAR as u32);
const X86_INS_SHL: InsnId = InsnId(X86Insn::X86_INS_SHL as u32);
const X86_INS_SHR: InsnId = InsnId(X86Insn::X86_INS_SHR as u32);
const X86_INS_ADD: InsnId = InsnId(X86Insn::X86_INS_ADD as u32);
const X86_INS_AND: InsnId = InsnId(X86Insn::X86_INS_AND as u32);

// PossibleTaint, DataTransfer.
const X86_INS_MOV: InsnId = InsnId(X86Insn::X86_INS_MOV as u32);
// DataTransfer.
const X86_INS_XCHG: InsnId = InsnId(X86Insn::X86_INS_XCHG as u32);
const X86_INS_LEA: InsnId = InsnId(X86Insn::X86_INS_LEA as u32);
const X86_INS_MOVZX: InsnId = InsnId(X86Insn::X86_INS_MOVZX as u32);
const X86_INS_MOVSX: InsnId = InsnId(X86Insn::X86_INS_MOVSX as u32);

// Unary.
const X86_INS_NEG: InsnId = InsnId(X86Insn::X86_INS_NEG as u32);
const X86_INS_NOT: InsnId = InsnId(X86Insn::X86_INS_NOT as u32);
const X86_INS_POP: InsnId = InsnId(X86Insn::X86_INS_POP as u32);
const X86_INS_DEC: InsnId = InsnId(X86Insn::X86_INS_DEC as u32);
const X86_INS_INC: InsnId = InsnId(X86Insn::X86_INS_INC as u32);

// BinaryCMP.
const X86_INS_TEST: InsnId = InsnId(X86Insn::X86_INS_TEST as u32);
const X86_INS_CMP: InsnId = InsnId(X86Insn::X86_INS_CMP as u32);

#[cfg(test)]
mod tests {
    use crate::gdb::*;
    use gdb_command::registers::Registers;
    use gdb_command::siginfo::Siginfo;
    #[test]
    fn test_call_av_x86_taint() {
        let data: &[u8] = &[0x8b, 0x00, 0x8b, 0x00, 0xff, 0xd0];
        let expected_class = ExecutionClass::find("CallAvTainted").unwrap();
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build();

        if let Ok(cs) = cs {
            if let Ok(insns) = cs.disasm_all(data, 0) {
                if let Ok(result) = check_taint(&cs, &insns) {
                    assert_eq!(expected_class, result);
                } else {
                    unreachable!();
                }
            }
        }
    }
    #[test]
    fn test_call_av_x64() {
        let data: &[u8] = &[0x48, 0x8b, 0x00, 0x48, 0x8b, 0x00, 0xff, 0xd0];
        let expected_class = ExecutionClass::find("CallAvTainted").unwrap();
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build();

        if let Ok(cs) = cs {
            if let Ok(insns) = cs.disasm_all(data, 0) {
                if let Ok(result) = check_taint(&cs, &insns) {
                    assert_eq!(expected_class, result);
                } else {
                    unreachable!();
                }
            }
        }
    }
    #[test]
    fn test_dest_av_x64() {
        let data: &[u8] = &[0x48, 0x8b, 0x00, 0x48, 0x01, 0xc2, 0x48, 0x89, 0x02];
        let expected_class = ExecutionClass::find("DestAvTainted").unwrap();
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build();

        if let Ok(cs) = cs {
            if let Ok(insns) = cs.disasm_all(data, 0) {
                if let Ok(result) = check_taint(&cs, &insns) {
                    assert_eq!(expected_class, result);
                } else {
                    unreachable!();
                }
            }
        }
    }

    #[test]
    fn test_dest_av_x86_taint() {
        let data: &[u8] = &[0x8b, 0x00, 0x01, 0xc2, 0x89, 0x02];
        let expected_class = ExecutionClass::find("DestAvTainted").unwrap();
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build();

        if let Ok(cs) = cs {
            if let Ok(insns) = cs.disasm_all(data, 0) {
                if let Ok(result) = check_taint(&cs, &insns) {
                    assert_eq!(expected_class, result);
                } else {
                    unreachable!();
                }
            }
        }
    }

    #[test]
    fn test_jmp_untainted_x86() {
        let data: &[u8] = &[0x8b, 0x00, 0x01, 0xc2, 0xff, 0xe3];
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build();

        if let Ok(cs) = cs {
            if let Ok(insns) = cs.disasm_all(data, 0) {
                if check_taint(&cs, &insns).is_ok() {
                    unreachable!()
                }
            }
        }
    }

    #[test]
    fn test_jump_av_arm() {
        //rasm2 -a arm -b 32 'ldr r0, [r0]; mov r1, r0; and r1, 0x1; ldr r0, [r1]; blx r0'
        let data: &[u8] = &[
            0x00, 0x00, 0x90, 0xe5, 0x00, 0x10, 0xa0, 0xe1, 0x01, 0x10, 0x01, 0xe2, 0x00, 0x00,
            0x91, 0xe5, 0x30, 0xff, 0x2f, 0xe1,
        ];
        let expected_class = ExecutionClass::find("BranchAvTainted").unwrap();
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .endian(capstone::Endian::Little)
            .detail(true)
            .build();

        if let Ok(cs) = cs {
            if let Ok(insns) = cs.disasm_all(data, 0) {
                if let Ok(result) = check_taint(&cs, &insns) {
                    assert_eq!(expected_class, result);
                } else {
                    unreachable!();
                }
            }
        }
    }
    #[test]
    fn test_dest_av_arm() {
        //rasm2 -a arm -b 32 'ldr r0, [r0]; mov r1, r0; orr r1, 0x1; ldr r0, [r1]; str r1, [r0]'
        let data: &[u8] = &[
            0x00, 0x00, 0x90, 0xe5, 0x00, 0x10, 0xa0, 0xe1, 0x01, 0x10, 0x81, 0xe3, 0x00, 0x00,
            0x91, 0xe5, 0x00, 0x10, 0x80, 0xe5,
        ];
        let expected_class = ExecutionClass::find("DestAvTainted").unwrap();
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .endian(capstone::Endian::Little)
            .detail(true)
            .build();

        if let Ok(cs) = cs {
            if let Ok(insns) = cs.disasm_all(data, 0) {
                if let Ok(result) = check_taint(&cs, &insns) {
                    assert_eq!(expected_class, result);
                } else {
                    unreachable!();
                }
            }
        }
    }

    #[test]
    fn test_bl_arm() {
        //rasm2 -a arm -b 32 'ldr r0, [r0]; mov r1, r0; rsb r1, 0x1; bl 0x1 '
        let data: &[u8] = &[
            0x00, 0x00, 0x90, 0xe5, 0x00, 0x10, 0xa0, 0xe1, 0x01, 0x10, 0x61, 0xe2, 0xfb, 0xff,
            0xff, 0xeb,
        ];
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .endian(capstone::Endian::Little)
            .detail(true)
            .build();

        if let Ok(cs) = cs {
            if let Ok(insns) = cs.disasm_all(data, 0) {
                if check_taint(&cs, &insns).is_ok() {
                    unreachable!();
                }
            }
        }
    }

    #[test]
    fn test_dest_av_x86() {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build();
        if let Ok(cs) = cs {
            let sig = Siginfo {
                si_signo: SIGINFO_SIGSEGV,
                si_code: 2,
                si_errno: 0,
                si_addr: 0xdeadbeaf,
            };

            let machine = MachineInfo {
                byte_width: 4,
                endianness: Endian::Little,
                arch: header::EM_386,
            };
            let mut registers = Registers::new();
            registers.insert("eax".to_string(), 0xdeadbeaf);
            let context = GdbContext {
                siginfo: sig,
                registers,
                mappings: MappedFiles::new(),
                pc_memory: MemoryObject {
                    address: 0x0,
                    data: vec![0x8b, 0x00, 0x01, 0xc2, 0x89, 0x02],
                },
                machine,
                stacktrace: Vec::new(),
            };
            let data: &[u8] = &[0x8b, 0x00, 0x01, 0xc2, 0x89, 0x02];
            let insns = cs.disasm_all(data, 0).unwrap();
            let expected_class = ExecutionClass::find("DestAvTainted").unwrap();
            if let Ok(res) = GdbContext::analyze_instructions(&cs, &insns, &context) {
                assert_eq!(res, expected_class);
            } else {
                unreachable!();
            }
        }
    }
    #[test]
    fn test_call_av_x86() {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build();
        if let Ok(cs) = cs {
            let sig = Siginfo {
                si_signo: SIGINFO_SIGSEGV,
                si_code: 2,
                si_errno: 0,
                si_addr: 0xdeadbeaf,
            };
            let machine = MachineInfo {
                byte_width: 4,
                endianness: Endian::Little,
                arch: header::EM_386,
            };
            let mut registers = Registers::new();
            registers.insert("eax".to_string(), 0xdeadbeaf);
            let context = GdbContext {
                siginfo: sig,
                registers,
                mappings: MappedFiles::new(),
                pc_memory: MemoryObject {
                    address: 0x0,
                    data: vec![0x8b, 0x00, 0x8b, 0x00, 0xff, 0xd0],
                },
                machine,
                stacktrace: Vec::new(),
            };
            let data: &[u8] = &[0x8b, 0x00, 0x8b, 0x00, 0xff, 0xd0];
            let insns = cs.disasm_all(data, 0).unwrap();
            let expected_class = ExecutionClass::find("CallAvTainted").unwrap();
            if let Ok(res) = GdbContext::analyze_instructions(&cs, &insns, &context) {
                assert_eq!(res, expected_class);
            } else {
                unreachable!();
            }
        }
    }
}
