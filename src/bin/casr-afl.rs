extern crate anyhow;
extern crate casr;
extern crate clap;
extern crate goblin;
#[macro_use]
extern crate log;

use anyhow::{bail, Context};
use clap::{App, Arg};
use simplelog::*;

use casr::error;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Default)]
struct AflCrashInfo {
    /// Path to crash input.
    pub path: PathBuf,
    /// Target command line args.
    pub target_args: Vec<String>,
    /// Stdin.
    pub is_stdin: bool,
    /// ASAN.
    pub is_asan: bool,
}

fn main() -> error::Result<()> {
    let matches = App::new("casr-afl")
        .version("2.1.1")
        .author("Andrey Fedotov  <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>")
        .about("Triage crashes found by AFL++")
        .term_width(90)
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .short('l')
                .takes_value(true)
                .default_value("info")
                .possible_values(&["info", "debug"])
                .help("Logging level")
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .takes_value(true)
                .value_name("INPUT_DIR")
                .required(true)
                .help("AFL++ work directory")
                .validator(|arg| {
                    let i_dir = Path::new(arg);
                    if !i_dir.exists() {
                        bail!("Input directory doesn't exists.");
                    }
                    if !i_dir.is_dir() {
                        bail!("Input path should be an AFL++ work directory.");
                    }
                    Ok(())
                })
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .takes_value(true)
                .required(true)
                .value_name("OUTPUT_DIR")
                .help("Output directory with triaged reports")
        )
        .arg(
            Arg::new("no-cluster")
                .long("no-cluster")
                .help("Do not cluster CASR reports")
        )
        .get_matches();

    // Init log.
    let log_level = if matches.value_of("log-level").unwrap() == "debug" {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let _ = TermLogger::init(
        log_level,
        ConfigBuilder::new().set_time_to_local(true).build(),
        TerminalMode::Mixed,
    );

    // Get all crashes.
    let mut crashes: Vec<AflCrashInfo> = Vec::new();
    for node_dir in fs::read_dir(matches.value_of("input").unwrap())? {
        let path = node_dir?.path();
        if !path.is_dir() {
            continue;
        }

        // Get crashes from one node.
        let mut crash_info = AflCrashInfo::default();
        let fuzzer_stats_path = path.join("fuzzer_stats");
        if let Ok(fuzzer_stats) = fs::read_to_string(&fuzzer_stats_path) {
            let mut rev_lines = fuzzer_stats.lines().rev();
            if let Some(cmd_line) = rev_lines.next() {
                if cmd_line.starts_with("command_line") {
                    if let Some((_, target_cmd)) = cmd_line.split_once("--") {
                        crash_info.target_args = target_cmd
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect();
                        crash_info.is_stdin = !target_cmd.contains("@@");
                        // Check if binary with ASAN
                        if let Some(target_mode) = rev_lines.next() {
                            if target_mode.contains("unicorn") {
                                error!("casr-afl doesn't support unicorn mode.");
                                continue;
                            }
                            if !target_mode.contains("qemu") {
                                // Check for ASAN symbols.
                                if let Some(target) = crash_info.target_args.first() {
                                    if let Ok(buffer) = fs::read(Path::new(target)) {
                                        if let Ok(elf) = goblin::elf::Elf::parse(&buffer) {
                                            for sym in elf.syms.iter() {
                                                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                                                    if name.contains("__asan") {
                                                        crash_info.is_asan = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        } else {
                                            error!(
                                                "Fuzz target: {} must be an ELF executable.",
                                                target
                                            );
                                            continue;
                                        }
                                    } else {
                                        error!("Couldn't read fuzz target binary: {}.", target);
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    error!(
                        "Couldn't find command_line: in {}.",
                        fuzzer_stats_path.display()
                    );
                    continue;
                }
            } else {
                error!("{} is empty.", fuzzer_stats_path.display());
                continue;
            }
        } else {
            error!("Couldn't read {}.", fuzzer_stats_path.display());
            continue;
        }

        // Push crash paths.
        for crash in fs::read_dir(path.join("crashes"))? {
            let crash_path = crash?.path();
            if crash_path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("id:")
            {
                crash_info.path = crash_path.to_path_buf();
                crashes.push(crash_info.clone());
            }
        }
    }

    // Generate CASR reports.
    info!("Generating CASR reports...");
    let output_dir = Path::new(matches.value_of("output").unwrap());
    if !output_dir.exists() {
        fs::create_dir(&output_dir).with_context(|| {
            format!("Couldn't create output directory {}", output_dir.display())
        })?;
    }

    for crash in crashes {
        let mut args: Vec<String> = vec!["-o".to_string()];
        if crash.is_asan {
            args.push(format!(
                "{}.casrep",
                output_dir.join(crash.path.file_name().unwrap()).display()
            ));
        } else {
            args.push(format!(
                "{}.gdb.casrep",
                output_dir.join(crash.path.file_name().unwrap()).display()
            ));
        }
        if crash.is_stdin {
            args.push("--stdin".to_string());
            args.push(crash.path.to_str().unwrap().to_string());
            args.push("--".to_string());
            args.extend_from_slice(&crash.target_args);
        } else {
            args.push("--".to_string());
            args.extend_from_slice(&crash.target_args);
            if let Some(at_index) = args.iter().position(|s| s.contains("@@")) {
                let input = args[at_index].replace("@@", crash.path.to_str().unwrap());
                args[at_index] = input;
            }
        }
        let tool = if crash.is_asan {
            "casr-san"
        } else {
            "casr-gdb"
        };
        debug!("{} {}", tool, args.join(" "));
        let casr_cmd = Command::new(tool)
            .args(&args)
            .output()
            .with_context(|| format!("Couldn't launch {}", tool))?;
        if !casr_cmd.status.success() {
            let err = String::from_utf8_lossy(&casr_cmd.stderr)
                .lines()
                .collect::<Vec<&str>>()
                .join(" ");
            if err.contains("Program terminated (no crash)") {
                warn!("{}: no crash on input {}", tool, crash.path.display());
            } else {
                error!("{} for input: {}", err, crash.path.display());
            }
        }
    }

    // Deduplicate reports.
    info!("Deduplicating CASR reports...");
    let casr_cluster_d = Command::new("casr-cluster")
        .arg("-d")
        .arg(matches.value_of("output").unwrap())
        .output()
        .with_context(|| "Couldn't launch casr-cluster".to_string())?;

    if casr_cluster_d.status.success() {
        info!(
            "{}",
            String::from_utf8_lossy(&casr_cluster_d.stdout)
                .lines()
                .collect::<Vec<&str>>()
                .join(". ")
        );
    } else {
        error!(
            "{}",
            String::from_utf8_lossy(&casr_cluster_d.stderr)
                .lines()
                .collect::<Vec<&str>>()
                .join(" ")
        );
    }

    if !matches.is_present("no-cluster") {
        info!("Clustering CASR reports...");
        let casr_cluster_c = Command::new("casr-cluster")
            .arg("-c")
            .arg(matches.value_of("output").unwrap())
            .arg(matches.value_of("output").unwrap())
            .output()
            .with_context(|| "Couldn't launch casr-cluster".to_string())?;

        if casr_cluster_c.status.success() {
            info!(
                "{}",
                String::from_utf8_lossy(&casr_cluster_c.stdout)
                    .lines()
                    .collect::<Vec<&str>>()
                    .join(" ")
            );
        } else {
            error!(
                "{}",
                String::from_utf8_lossy(&casr_cluster_c.stderr)
                    .lines()
                    .collect::<Vec<&str>>()
                    .join(" ")
            );
        }

        // Remove reports from deduplication phase. They are in clusters now.
        for casrep in fs::read_dir(&output_dir)? {
            let casrep_path = casrep?.path();
            if let Some(ext) = casrep_path.extension() {
                if ext == "casrep" {
                    let _ = fs::remove_file(casrep_path);
                }
            }
        }
    }

    Ok(())
}
