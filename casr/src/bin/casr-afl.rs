use casr::util;

use anyhow::{bail, Context, Result};
use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Arg, ArgAction,
};
use log::{debug, error, info, warn};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use walkdir::WalkDir;

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
    /// Input file argument index starting from argv\[1\], None for stdin.
    pub at_index: Option<usize>,
    /// ASAN.
    pub is_asan: bool,
}

impl<'a> AflCrashInfo {
    /// Generate Casr report for crash.
    ///
    /// # Arguments
    ///
    /// * `output_dir` - save report to specified directory or use the same directory as crash
    ///
    /// * `timeout` - target program timeout (in seconds)
    pub fn run_casr<T: Into<Option<&'a Path>>>(
        &self,
        output_dir: T,
        timeout: u64,
    ) -> anyhow::Result<()> {
        let mut args: Vec<String> = vec!["-o".to_string()];
        let report_path = if let Some(out) = output_dir.into() {
            out.join(self.path.file_name().unwrap())
        } else {
            self.path.clone()
        };
        if self.is_asan {
            args.push(format!("{}.casrep", report_path.display()));
        } else {
            args.push(format!("{}.gdb.casrep", report_path.display()));
        }

        if self.at_index.is_none() {
            args.push("--stdin".to_string());
            args.push(self.path.to_str().unwrap().to_string());
        }
        if timeout != 0 {
            args.append(&mut vec!["-t".to_string(), timeout.to_string()]);
        }
        args.push("--".to_string());
        args.extend_from_slice(&self.target_args);
        if let Some(at_index) = self.at_index {
            let input = args[at_index + 4].replace("@@", self.path.to_str().unwrap());
            args[at_index + 4] = input;
        }

        let tool = if self.is_asan { "casr-san" } else { "casr-gdb" };
        let mut casr_cmd = Command::new(tool);
        casr_cmd.args(&args);
        debug!("{:?}", casr_cmd);

        // Get output
        let casr_output = casr_cmd
            .output()
            .with_context(|| format!("Couldn't launch {casr_cmd:?}"))?;

        if !casr_output.status.success() {
            let err = String::from_utf8_lossy(&casr_output.stderr);
            if err.contains("Program terminated (no crash)") {
                warn!("{}: no crash on input {}", tool, self.path.display());
            } else {
                error!("{} for input: {}", err.trim(), self.path.display());
            }
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-afl")
        .version(clap::crate_version!())
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
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .action(ArgAction::Set)
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution [default: disabled]")
                .value_parser(clap::value_parser!(u64).range(1..))
        )
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
                .value_parser(clap::value_parser!(PathBuf))
                .help("Output directory with triaged reports")
        )
        .arg(
            Arg::new("no-cluster")
                .action(ArgAction::SetTrue)
                .long("no-cluster")
                .help("Do not cluster CASR reports")
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .required(false)
                .num_args(1..)
                .last(true)
                .help("Add \"-- ./gdb_fuzz_target <arguments>\" to generate additional crash reports with casr-gdb (e.g., test whether program crashes without sanitizers)"),
        )
        .get_matches();

    // Init log.
    util::initialize_logging(&matches);

    // Get output dir
    let output_dir = matches.get_one::<PathBuf>("output").unwrap();
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("Couldn't create output directory {}", output_dir.display())
        })?;
    } else if output_dir.read_dir()?.next().is_some() {
        bail!("Output directory is not empty.");
    }

    // Get optional gdb fuzz target args.
    let gdb_argv: Vec<String> = if let Some(argvs) = matches.get_many::<String>("ARGS") {
        argvs.cloned().collect()
    } else {
        Vec::new()
    };

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
        for crash in path
            .read_dir()?
            .flatten()
            .filter(|e| e.file_name().into_string().unwrap().starts_with("crashes"))
            .flat_map(|e| e.path().read_dir())
            .flatten()
            .flatten()
            .filter(|e| e.file_name().into_string().unwrap().starts_with("id:"))
        {
            let mut info = crash_info.clone();
            info.path = crash.path();
            crashes.insert(crash.file_name().into_string().unwrap(), info);
        }
    }

    // Get timeout
    let timeout = if let Some(timeout) = matches.get_one::<u64>("timeout") {
        *timeout
    } else {
        0
    };

    // Get number of threads
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
        crashes
            .par_iter()
            .try_for_each(|(_, crash)| crash.run_casr(output_dir.as_path(), timeout))
    })?;

    // Deduplicate reports.
    if output_dir.read_dir()?.count() < 2 {
        info!("There are less than 2 CASR reports, nothing to deduplicate.");
        return summarize_results(output_dir, &crashes, &gdb_argv, num_of_threads, timeout);
    }
    info!("Deduplicating CASR reports...");
    let casr_cluster_d = Command::new("casr-cluster")
        .arg("-d")
        .arg(output_dir.clone().into_os_string())
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
            return summarize_results(output_dir, &crashes, &gdb_argv, num_of_threads, timeout);
        }
        info!("Clustering CASR reports...");
        let casr_cluster_c = Command::new("casr-cluster")
            .arg("-c")
            .arg(output_dir.clone().into_os_string())
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

    summarize_results(output_dir, &crashes, &gdb_argv, num_of_threads, timeout)
}

/// Copy crashes next to reports and print summary.
/// Run casr-gdb on uninstrumented binary if specified in ARGS.
///
/// # Arguments
///
/// * `dir` - directory with casr reports
///
/// * `crashes` - crashes info
///
/// * `gdb_args` - run casr-gdb on uninstrumented binary if specified
///
/// * `jobs` - number of threads for casr-gdb reports generation
///
/// * `timeout` - target program timeout
fn summarize_results(
    dir: &Path,
    crashes: &HashMap<String, AflCrashInfo>,
    gdb_args: &Vec<String>,
    jobs: usize,
    timeout: u64,
) -> Result<()> {
    // Copy crashes next to reports
    copy_crashes(dir, crashes)?;

    if !gdb_args.is_empty() {
        // Run casr-gdb on uninstrumented binary.
        let crashes: Vec<_> = WalkDir::new(dir)
            .into_iter()
            .flatten()
            .map(|e| e.into_path())
            .filter(|e| e.is_file())
            .filter(|e| e.extension().is_none() || e.extension().unwrap() != "casrep")
            .filter(|e| !Path::new(format!("{}.gdb.casrep", e.display()).as_str()).exists())
            .collect();
        let num_of_threads = jobs.min(crashes.len());
        if num_of_threads > 0 {
            info!("casr-gdb: adding crash reports...");
            info!("Using {} threads", num_of_threads);
            let custom_pool = rayon::ThreadPoolBuilder::new()
                .num_threads(num_of_threads)
                .build()
                .unwrap();
            let at_index = gdb_args.iter().skip(1).position(|s| s.contains("@@"));
            custom_pool.install(|| {
                crashes.par_iter().try_for_each(|crash| {
                    AflCrashInfo {
                        path: crash.to_path_buf(),
                        target_args: gdb_args.clone(),
                        at_index,
                        is_asan: false,
                    }
                    .run_casr(None, timeout)
                })
            })?;
        }
    }

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
