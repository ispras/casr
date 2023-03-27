extern crate anyhow;
extern crate casr;
extern crate clap;
extern crate goblin;
#[macro_use]
extern crate log;

use anyhow::{bail, Context, Result};
use clap::{App, Arg};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use simplelog::*;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Default)]
/// Information about crash to reproduce it.
struct AflCrashInfo {
    /// Path to crash input.
    pub path: PathBuf,
    /// Target command line args.
    pub target_args: Vec<String>,
    /// Input index, None for stdin.
    pub at_index: Option<usize>,
    /// ASAN.
    pub is_asan: bool,
}

fn main() -> Result<()> {
    let matches = App::new("casr-afl")
        .version("2.5.1")
        .author("Andrey Fedotov <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>")
        .about("Triage crashes found by AFL++")
        .term_width(90)
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .short('l')
                .takes_value(true)
                .default_value("info")
                .possible_values(["info", "debug"])
                .help("Logging level")
        )
        .arg(Arg::new("jobs")
            .long("jobs")
            .short('j')
            .takes_value(true)
            .help("Number of parallel jobs for generating CASR reports [default: half of cpu cores]")
            .validator(|arg| {
                if let Ok(x) = arg.parse::<u64>() {
                    if x > 0 {
                        return Ok(());
                    }
                }
                Err(String::from("Couldn't parse jobs value"))
        }))
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
                        bail!("Input directory doesn't exist.");
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
        ConfigBuilder::new()
            .set_time_offset_to_local()
            .unwrap()
            .build(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    );

    let output_dir = Path::new(matches.value_of("output").unwrap());
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("Couldn't create output directory {}", output_dir.display())
        })?;
    } else if output_dir.read_dir()?.next().is_some() {
        bail!("Output directory is not empty.");
    }

    // Get all crashes.
    let mut crashes: HashMap<String, AflCrashInfo> = HashMap::new();
    for node_dir in fs::read_dir(matches.value_of("input").unwrap())? {
        let path = node_dir?.path();
        if !path.is_dir() {
            continue;
        }

        // Get crashes from one node.
        let mut crash_info = AflCrashInfo::default();
        let cmdline_path = path.join("cmdline");
        if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
            crash_info.target_args = cmdline.split_whitespace().map(|s| s.to_string()).collect();
            crash_info.at_index = crash_info
                .target_args
                .iter()
                .skip(1)
                .position(|s| s.contains("@@"));

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
                        error!("Fuzz target: {} must be an ELF executable.", target);
                        continue;
                    }
                } else {
                    error!("Couldn't read fuzz target binary: {}.", target);
                    continue;
                }
            } else {
                error!("{} is empty.", cmdline);
                continue;
            }
        } else {
            error!("Couldn't read {}.", cmdline_path.display());
            continue;
        }

        // Push crash paths.
        for crash in fs::read_dir(path.join("crashes"))? {
            let crash_path = crash?.path();
            let fname = crash_path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();

            if fname.starts_with("id:") {
                crash_info.path = crash_path.to_path_buf();
                crashes.insert(fname, crash_info.clone());
            }
        }
    }

    let jobs = if let Some(jobs) = matches.value_of("jobs") {
        jobs.parse::<usize>().unwrap()
    } else {
        std::cmp::max(1, num_cpus::get() / 2)
    };
    let num_of_threads = jobs.min(crashes.len());
    let custom_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_of_threads)
        .build()
        .unwrap();

    // Generate CASR reports.
    info!("Generating CASR reports...");
    info!("Using {} threads", num_of_threads);
    custom_pool.install(|| {
        crashes.par_iter().try_for_each(|(_, crash)| {
            let mut args: Vec<String> = vec!["-o".to_string()];
            let report_path = output_dir.join(crash.path.file_name().unwrap());
            if crash.is_asan {
                args.push(format!("{}.casrep", report_path.display()));
            } else {
                args.push(format!("{}.gdb.casrep", report_path.display()));
            }

            if let Some(at_index) = crash.at_index {
                args.push("--".to_string());
                args.extend_from_slice(&crash.target_args);
                let input = args[at_index + 4].replace("@@", crash.path.to_str().unwrap());
                args[at_index + 4] = input;
            } else {
                args.push("--stdin".to_string());
                args.push(crash.path.to_str().unwrap().to_string());
                args.push("--".to_string());
                args.extend_from_slice(&crash.target_args);
            }
            let tool = if crash.is_asan {
                "casr-san"
            } else {
                "casr-gdb"
            };
            let mut casr_cmd = Command::new(tool);
            casr_cmd.args(&args);
            debug!("{:?}", casr_cmd);
            let casr_output = casr_cmd
                .output()
                .with_context(|| format!("Couldn't launch {casr_cmd:?}"))?;
            if !casr_output.status.success() {
                let err = String::from_utf8_lossy(&casr_output.stderr);
                if err.contains("Program terminated (no crash)") {
                    warn!("{}: no crash on input {}", tool, crash.path.display());
                } else {
                    error!("{} for input: {}", err, crash.path.display());
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    })?;

    // Deduplicate reports.
    if output_dir.read_dir()?.count() < 2 {
        info!("There are less than 2 CASR reports, nothing to deduplicate.");
        return Ok(());
    }
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
        bail!("{}", String::from_utf8_lossy(&casr_cluster_d.stderr));
    }

    if !matches.is_present("no-cluster") {
        if output_dir.read_dir()?.count() < 2 {
            info!("There are less than 2 CASR reports, nothing to cluster.");
            return Ok(());
        }
        info!("Clustering CASR reports...");
        let casr_cluster_c = Command::new("casr-cluster")
            .arg("-c")
            .arg(matches.value_of("output").unwrap())
            .output()
            .with_context(|| "Couldn't launch casr-cluster".to_string())?;

        if casr_cluster_c.status.success() {
            info!(
                "{}",
                String::from_utf8_lossy(&casr_cluster_c.stdout).trim_end()
            );
        } else {
            error!("{}", String::from_utf8_lossy(&casr_cluster_c.stderr));
        }

        // Remove reports from deduplication phase. They are in clusters now.
        for casrep in fs::read_dir(output_dir)? {
            let casrep_path = casrep?.path();
            if let Some(ext) = casrep_path.extension() {
                if ext == "casrep" {
                    let _ = fs::remove_file(casrep_path);
                }
            }
        }
    }

    // Copy crashes next to reports
    copy_crashes(output_dir, &crashes)?;

    // print summary
    let status = Command::new("casr-cli")
        .arg(matches.value_of("output").unwrap())
        .stderr(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .status()
        .with_context(|| "Couldn't launch casr-cli".to_string())?;

    if !status.success() {
        error!("casr-cli exited with status {status}");
    }

    Ok(())
}

/// Copy recursively crash inputs next to casr reports
///
/// # Arguments
///
/// `dir` - directory with casr reports
fn copy_crashes(dir: &Path, crashes: &HashMap<String, AflCrashInfo>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let mut e = entry?.path();
        let fname = e.file_name().unwrap().to_str().unwrap();
        if fname.starts_with("cl") && e.is_dir() {
            copy_crashes(&e, crashes)?;
        } else if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
            e = e.with_extension("");
            if e.extension().is_some() && e.extension().unwrap() == "gdb" {
                e = e.with_extension("");
            }
            let fname = e.file_name().unwrap().to_str().unwrap();
            if let Some(crash) = crashes.get(fname) {
                let _ = fs::copy(&crash.path, e);
            }
        }
    }

    Ok(())
}
