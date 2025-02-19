//! Post-fuzzing crash analysis module: create, deduplicate, cluster CASR reports
//! and print overall summary.
use crate::util::{get_path, initialize_dirs, log_progress};

use std::collections::HashMap;
use std::fs;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::RwLock;

use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use walkdir::WalkDir;

#[derive(Debug, Clone, Default)]
/// Information about crash to reproduce it.
pub struct CrashInfo {
    /// Path to crash input.
    pub path: PathBuf,
    /// Target command line args.
    pub target_args: Vec<String>,
    /// Target environment variables.
    pub envs: HashMap<String, String>,
    /// Input file argument index starting from argv\[1\], None for stdin.
    pub at_index: Option<usize>,
    /// Casr tool that should be run on this crash.
    pub casr_tool: PathBuf,
}

impl<'a> CrashInfo {
    /// Generate Casr report for crash.
    ///
    /// # Arguments
    ///
    /// * `output_dir` - save report to specified directory or use the same directory as crash
    ///
    /// * `timeout` - target program timeout (in seconds)
    pub fn run_casr<T: Into<Option<&'a Path>>>(&self, output_dir: T, timeout: u64) -> Result<()> {
        let tool = &self.casr_tool;
        let tool_name = tool.file_name().unwrap().to_str().unwrap();
        let mut args: Vec<String> = vec!["-o".to_string()];
        let (report_path, output_dir) = if let Some(out) = output_dir.into() {
            (out.join(self.path.file_name().unwrap()), out)
        } else {
            (self.path.clone(), self.path.parent().unwrap())
        };
        if tool_name.eq("casr-gdb") {
            args.push(format!("{}.gdb.casrep", report_path.display()));
        } else {
            args.push(format!("{}.casrep", report_path.display()));
        }
        if self.at_index.is_none() || self.at_index == Some(0) {
            args.push("--stdin".to_string());
            args.push(self.path.to_str().unwrap().to_string());
        }
        if timeout != 0 {
            args.push("-t".to_string());
            args.push(timeout.to_string());
        }
        args.push("--".to_string());
        if tool_name.eq("casr-python") {
            args.push("python3".to_string());
        }
        let offset = args.len();
        args.extend_from_slice(&self.target_args);
        if let Some(at_index) = self.at_index {
            let input = args[at_index + offset].replace("@@", self.path.to_str().unwrap());
            args[at_index + offset] = input;
        }

        let mut casr_cmd = Command::new(tool);
        casr_cmd.args(&args);
        casr_cmd.envs(&self.envs);

        // Add envs
        if self.target_args.iter().any(|x| x.eq("-detect_leaks=0")) {
            let asan_options = std::env::var("ASAN_OPTIONS").unwrap_or_default();
            casr_cmd.env(
                "ASAN_OPTIONS",
                if asan_options.is_empty() {
                    "detect_leaks=0".to_string()
                } else {
                    format!("{asan_options},detect_leaks=0",)
                },
            );
        }

        debug!("{:?}", casr_cmd);

        // Get output
        let casr_output = casr_cmd
            .output()
            .with_context(|| format!("Couldn't launch {casr_cmd:?}"))?;

        if !casr_output.status.success() {
            let err = String::from_utf8_lossy(&casr_output.stderr);
            if err.contains("Timeout") {
                let mut timeout_name = self
                    .path
                    .file_name()
                    .unwrap()
                    .to_os_string()
                    .into_string()
                    .unwrap();
                if let Some(idx) = timeout_name.find('-') {
                    timeout_name.replace_range(..idx, "timeout");
                }
                let timeout_path = output_dir.join("timeout").join(timeout_name);
                if fs::copy(&self.path, timeout_path).is_err() {
                    error!("Error occurred while copying the file: {:?}", self.path);
                }
            } else if err.contains("Out of memory") {
                let mut oom_name = self
                    .path
                    .file_name()
                    .unwrap()
                    .to_os_string()
                    .into_string()
                    .unwrap();
                if let Some(idx) = oom_name.find('-') {
                    oom_name.replace_range(..idx, "oom");
                }
                let oom_path = output_dir.join("oom").join(oom_name);
                if fs::copy(&self.path, oom_path).is_err() {
                    error!("Error occurred while copying the file: {:?}", self.path);
                }
            } else if err.contains("Program terminated (no crash)") {
                warn!("{}: No crash on input {}", tool_name, self.path.display());
            } else {
                error!("{} for input: {}", err.trim(), self.path.display());
            }
        }

        Ok(())
    }
}

/// Perform crash analysis pipeline: Create, deduplicate and cluster CASR reports.
///
/// # Arguments
///
/// * `matches` - casr-afl/casr-libfuzzer arguments
///
/// * `crashes` - map of crashes, specified as a HashMap, where
///               key is crash input file name and value is CrashInfo structure
///
/// * `gdb_args` - casr-gdb target arguments. If they are empty, casr-gdb won't be launched.
pub fn fuzzing_crash_triage_pipeline(
    matches: &clap::ArgMatches,
    crashes: &HashMap<String, CrashInfo>,
    gdb_args: &[String],
) -> Result<()> {
    // Get casr-cluster path
    let casr_cluster = get_path("casr-cluster")?;

    if crashes.is_empty() {
        bail!("No crashes found");
    }

    let accum_mode = matches.contains_id("join");

    let output_dir = initialize_dirs(matches)?;

    let casrep_dir = if accum_mode {
        output_dir.join("casrep")
    } else {
        output_dir.to_path_buf()
    };

    // Get timeout
    let timeout = *matches.get_one::<u64>("timeout").unwrap();

    // Get number of threads
    let jobs = if let Some(jobs) = matches.get_one::<u32>("jobs") {
        *jobs as usize
    } else {
        std::cmp::max(1, num_cpus::get() / 2)
    };
    let num_of_threads = jobs.min(crashes.len()).max(1) + 1;
    let custom_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_of_threads)
        .build()
        .unwrap();

    info!("Analyzing {} files...", crashes.len());
    if timeout != 0 {
        info!("Timeout for target execution is {timeout} seconds");
    }
    // Generate CASR reports.
    info!("Generating CASR reports...");
    info!("Using {} threads", num_of_threads - 1);
    let counter = RwLock::new(0_usize);
    let total = crashes.len();
    custom_pool
        .join(
            || {
                crashes.par_iter().try_for_each(|(_, crash)| {
                    if let Err(e) = crash.run_casr(casrep_dir.as_path(), timeout) {
                        // Disable util::log_progress
                        *counter.write().unwrap() = total;
                        bail!(e);
                    };
                    *counter.write().unwrap() += 1;
                    Ok::<(), anyhow::Error>(())
                })
            },
            || log_progress(&counter, total),
        )
        .0?;

    // Deduplicate reports.
    if output_dir.read_dir()?.count() < 2 {
        info!("There are less than 2 CASR reports, nothing to deduplicate.");
        return summarize_results(matches, crashes, gdb_args);
    }
    info!("Deduplicating CASR reports...");
    let casr_cluster_d = Command::new(&casr_cluster)
        .arg("-d")
        .arg(casrep_dir.clone().into_os_string())
        .output()
        .with_context(|| format!("Couldn't launch {casr_cluster:?}"))?;

    if casr_cluster_d.status.success() {
        info!(
            "{}",
            String::from_utf8_lossy(&casr_cluster_d.stdout)
                .lines()
                .collect::<Vec<&str>>()
                .join(". ")
        );
    } else {
        bail!(
            "{}",
            String::from_utf8_lossy(&casr_cluster_d.stderr).trim_end()
        );
    }

    if !matches.get_flag("no-cluster") {
        if accum_mode {
            info!("Accumulating CASR reports...");
            let casr_cluster_u = Command::new(&casr_cluster)
                .arg("-u")
                .arg(casrep_dir.clone().into_os_string())
                .arg(output_dir.clone().into_os_string())
                .output()
                .with_context(|| format!("Couldn't launch {casr_cluster:?}"))?;

            if casr_cluster_u.status.success() {
                info!(
                    "{}",
                    String::from_utf8_lossy(&casr_cluster_u.stdout).trim_end()
                );
            } else {
                error!(
                    "{}",
                    String::from_utf8_lossy(&casr_cluster_u.stderr).trim_end()
                );
            }

            // Remove reports from deduplication phase. They are in clusters now.
            fs::remove_dir_all(casrep_dir)?;
        } else {
            if casrep_dir
                .read_dir()?
                .flatten()
                .map(|e| e.path())
                .filter(|e| e.extension().is_some() && e.extension().unwrap() == "casrep")
                .count()
                < 2
            {
                info!("There are less than 2 CASR reports, nothing to cluster.");
                return summarize_results(matches, crashes, gdb_args);
            }
            info!("Clustering CASR reports...");
            let casr_cluster_c = Command::new(&casr_cluster)
                .arg("-c")
                .arg(output_dir.clone().into_os_string())
                .output()
                .with_context(|| format!("Couldn't launch {casr_cluster:?}"))?;

            if casr_cluster_c.status.success() {
                info!(
                    "{}",
                    String::from_utf8_lossy(&casr_cluster_c.stdout).trim_end()
                );
            } else {
                error!(
                    "{}",
                    String::from_utf8_lossy(&casr_cluster_c.stderr).trim_end()
                );
            }

            // Remove reports from deduplication phase. They are in clusters now.
            for casrep in fs::read_dir(casrep_dir)?.flatten().map(|e| e.path()) {
                if let Some(ext) = casrep.extension() {
                    if ext == "casrep" {
                        let _ = fs::remove_file(casrep);
                    }
                }
            }
        }
    }

    summarize_results(matches, crashes, gdb_args)
}

/// Copy crashes next to reports and print summary.
/// Run casr-gdb on uninstrumented binary if specified in ARGS.
/// Print analysis statistic.
///
/// # Arguments
///
/// * `matches` - tool arguments
///
/// * `crashes` - set of crashes, specified as a CrashInfo structure
///
/// * `gdb_args` - casr-gdb target arguments. If they are empty, casr-gdb won't be launched.
fn summarize_results(
    matches: &clap::ArgMatches,
    crashes: &HashMap<String, CrashInfo>,
    gdb_args: &[String],
) -> Result<()> {
    // Get output dir
    let dir = matches.get_one::<PathBuf>("output").unwrap();
    // Copy crashes next to reports
    copy_crashes(dir, crashes)?;

    // Get timeout
    let timeout = *matches.get_one::<u64>("timeout").unwrap();

    // Get number of threads
    let jobs = if let Some(jobs) = matches.get_one::<u32>("jobs") {
        *jobs as usize
    } else {
        std::cmp::max(1, num_cpus::get() / 2)
    };

    if !gdb_args.is_empty() {
        let casr_gdb = get_path("casr-gdb")?;
        // Run casr-gdb on uninstrumented binary.
        let crashes: Vec<_> = WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_str().unwrap();
                !name.eq("oom") && !name.eq("timeout")
            })
            .flatten()
            .map(|e| e.into_path())
            .filter(|e| e.is_file())
            .filter(|e| e.extension().is_none() || e.extension().unwrap() != "casrep")
            .filter(|e| !Path::new(format!("{}.gdb.casrep", e.display()).as_str()).exists())
            .collect();
        if !crashes.is_empty() {
            let num_of_threads = jobs.min(crashes.len()) + 1;
            info!("casr-gdb: adding crash reports...");
            info!("Using {} threads", num_of_threads - 1);
            let counter = RwLock::new(0_usize);
            let total = crashes.len();
            let custom_pool = rayon::ThreadPoolBuilder::new()
                .num_threads(num_of_threads)
                .build()
                .unwrap();
            let at_index = gdb_args
                .iter()
                .skip(1)
                .position(|s| s.contains("@@"))
                .map(|x| x + 1);
            custom_pool
                .join(
                    || {
                        crashes.par_iter().try_for_each(|crash| {
                            if let Err(e) = (CrashInfo {
                                path: crash.to_path_buf(),
                                target_args: gdb_args.to_vec(),
                                envs: HashMap::new(),
                                at_index,
                                casr_tool: casr_gdb.clone(),
                            })
                            .run_casr(None, timeout)
                            {
                                // Disable util::log_progress
                                *counter.write().unwrap() = total;
                                bail!(e);
                            };
                            *counter.write().unwrap() += 1;
                            Ok::<(), anyhow::Error>(())
                        })
                    },
                    || log_progress(&counter, total),
                )
                .0?;
        }
    }

    let casr_cli = get_path("casr-cli")?;
    // Print summary
    let status = Command::new(casr_cli)
        .arg(dir)
        .stderr(std::process::Stdio::inherit())
        .stdout(std::io::stderr().as_fd().try_clone_to_owned()?)
        .status()
        .with_context(|| "Couldn't launch casr-cli".to_string())?;

    if !status.success() {
        error!("casr-cli exited with status {status}");
    }

    // Report ooms.
    let oom_dir = dir.join("oom");
    let oom_cnt = fs::read_dir(&oom_dir).unwrap().count();
    if oom_cnt != 0 {
        info!(
            "{} out of memory seeds are saved to {:?}",
            oom_cnt, &oom_dir
        );
    } else {
        fs::remove_dir_all(&oom_dir)?;
    }

    // Report timeouts.
    let timeout_dir = dir.join("timeout");
    let timeout_cnt = fs::read_dir(&timeout_dir).unwrap().count();
    if timeout_cnt != 0 {
        info!(
            "{} timeout seeds are saved to {:?}",
            timeout_cnt, &timeout_dir
        );
    } else {
        fs::remove_dir_all(&timeout_dir)?;
    }

    // Check bad reports.
    if let Ok(err_dir) = fs::read_dir(dir.join("clerr")) {
        warn!(
            "{} corrupted reports are saved to {:?}",
            err_dir
                .filter_map(|x| x.ok())
                .map(|x| x.path().display().to_string())
                .filter(|x| x.ends_with(".casrep"))
                .filter(|x| !x.ends_with(".gdb.casrep")
                    || !PathBuf::from(x.strip_suffix("gdb.casrep").unwrap().to_string() + "casrep")
                        .exists())
                .count(),
            &dir.join("clerr")
        );
    }

    Ok(())
}

/// Copy recursively crash inputs next to casr reports
///
/// # Arguments
///
/// `dir` - directory with casr reports
///
/// `crashes` - crashes info
fn copy_crashes(dir: &Path, crashes: &HashMap<String, CrashInfo>) -> Result<()> {
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
