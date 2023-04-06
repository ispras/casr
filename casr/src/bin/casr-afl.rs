use casr::util;

use anyhow::{bail, Context, Result};
use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Arg, ArgAction,
};
use log::{debug, error, info, warn};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

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
    let matches = clap::Command::new("casr-afl")
        .version("2.5.1")
        .author("Andrey Fedotov <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>")
        .about("Triage crashes found by AFL++")
        .term_width(90)
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .short('l')
                .action(ArgAction::Set)
                .default_value("info")
                .value_parser(["info", "debug"])
                .help("Logging level")
        )
        .arg(Arg::new("jobs")
            .long("jobs")
            .short('j')
            .action(ArgAction::Set)
            .help("Number of parallel jobs for generating CASR reports [default: half of cpu cores]")
            .value_parser(clap::value_parser!(u32).range(1..)))
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .action(ArgAction::Set)
                .value_name("INPUT_DIR")
                .required(true)
                .help("AFL++ work directory")
                .value_parser(move |arg: &str| {
                    let i_dir = Path::new(arg);
                    if !i_dir.exists() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(ContextKind::InvalidValue, ContextValue::String("Input directory doesn't exist.".to_owned()));
                        return Err(err);
                    }
                    if !i_dir.is_dir() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(ContextKind::InvalidValue, ContextValue::String("Input path should be an AFL++ work directory.".to_owned()));
                        return Err(err);
                    }
                    Ok(i_dir.to_path_buf())
                })
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .action(ArgAction::Set)
                .required(true)
                .value_name("OUTPUT_DIR")
                .help("Output directory with triaged reports")
        )
        .arg(
            Arg::new("no-cluster")
                .action(ArgAction::SetTrue)
                .long("no-cluster")
                .help("Do not cluster CASR reports")
        )
        .get_matches();

    // Init log.
    util::initialize_logging(&matches);

    let output_dir = Path::new(matches.get_one::<String>("output").unwrap());
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("Couldn't create output directory {}", output_dir.display())
        })?;
    } else if output_dir.read_dir()?.next().is_some() {
        bail!("Output directory is not empty.");
    }

    // Get all crashes.
    let mut crashes: HashMap<String, AflCrashInfo> = HashMap::new();
    for node_dir in fs::read_dir(matches.get_one::<PathBuf>("input").unwrap())? {
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

    let jobs = if let Some(jobs) = matches.get_one::<u32>("jobs") {
        *jobs as usize
    } else {
        std::cmp::max(1, num_cpus::get() / 2)
    };
    let num_of_threads = jobs.min(crashes.len()).max(1);
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
                    error!("{} for input: {}", err.trim(), crash.path.display());
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    })?;

    // Deduplicate reports.
    if output_dir.read_dir()?.count() < 2 {
        info!("There are less than 2 CASR reports, nothing to deduplicate.");
        return summarize_results(output_dir, &crashes);
    }
    info!("Deduplicating CASR reports...");
    let casr_cluster_d = Command::new("casr-cluster")
        .arg("-d")
        .arg(matches.get_one::<String>("output").unwrap())
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

    if !matches.get_flag("no-cluster") {
        if output_dir
            .read_dir()?
            .flatten()
            .map(|e| e.path())
            .filter(|e| e.extension().is_some() && e.extension().unwrap() == "casrep")
            .count()
            < 2
        {
            info!("There are less than 2 CASR reports, nothing to cluster.");
            return summarize_results(output_dir, &crashes);
        }
        info!("Clustering CASR reports...");
        let casr_cluster_c = Command::new("casr-cluster")
            .arg("-c")
            .arg(matches.get_one::<String>("output").unwrap())
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
        for casrep in fs::read_dir(output_dir)?.flatten().map(|e| e.path()) {
            if let Some(ext) = casrep.extension() {
                if ext == "casrep" {
                    let _ = fs::remove_file(casrep);
                }
            }
        }
    }

    summarize_results(output_dir, &crashes)
}

/// Copy crashes next to reports and print summary.
///
/// # Arguments
///
/// `dir` - directory with casr reports
/// `crashes` - crashes info
fn summarize_results(dir: &Path, crashes: &HashMap<String, AflCrashInfo>) -> Result<()> {
    // Copy crashes next to reports
    copy_crashes(dir, crashes)?;

    // Print summary
    let status = Command::new("casr-cli")
        .arg(dir)
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
/// `crashes` - crashes info
fn copy_crashes(dir: &Path, crashes: &HashMap<String, AflCrashInfo>) -> Result<()> {
    for e in fs::read_dir(dir)?.flatten().map(|x| x.path()) {
        if e.is_dir() && e.file_name().unwrap().to_str().unwrap().starts_with("cl") {
            copy_crashes(&e, crashes)?;
        } else if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
            let mut e = e.with_extension("");
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
