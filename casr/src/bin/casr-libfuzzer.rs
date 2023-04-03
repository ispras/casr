extern crate anyhow;
extern crate casr;
extern crate clap;
extern crate goblin;
#[macro_use]
extern crate log;

use casr::util;

use anyhow::{bail, Context, Result};
use clap::{App, Arg};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

fn main() -> Result<()> {
    let matches = App::new("casr-libfuzzer")
        .version("2.5.1")
        .author("Andrey Fedotov <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>, Ilya Yegorov <Yegorov_Ilya@ispras.ru>")
        .about("Triage crashes found by libFuzzer based fuzzer (C/C++/go-fuzz/Atheris)")
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
                .default_value(".")
                .value_name("INPUT_DIR")
                .help("Directory containing crashes found by libFuzzer")
                .validator(|arg| {
                    let i_dir = Path::new(arg);
                    if !i_dir.exists() {
                        bail!("Crash directory doesn't exist.");
                    }
                    if !i_dir.is_dir() {
                        bail!("Input path should be a directory.");
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
        .arg(
            Arg::new("ARGS")
                .multiple_values(true)
                .takes_value(true)
                .last(true)
                .help("Add \"-- ./fuzz_target <arguments>\""),
        )
        .get_matches();

    // Init log.
    util::initialize_logging(&matches);

    let input_dir = Path::new(matches.value_of("input").unwrap());

    let output_dir = Path::new(matches.value_of("output").unwrap());
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("Couldn't create output directory {}", output_dir.display())
        })?;
    } else if output_dir.read_dir()?.next().is_some() {
        bail!("Output directory is not empty.");
    }

    // Get fuzz target args.
    let argv: Vec<&str> = if let Some(argvs) = matches.values_of("ARGS") {
        argvs.collect()
    } else {
        bail!("Invalid fuzz target arguments");
    };

    let mut atheris_asan_lib = String::new();
    if argv[0].ends_with(".py") {
        // Get Atheris asan_with_fuzzer library path.
        let mut cmd = Command::new("python3");
        cmd.arg("-c")
            .arg("import atheris; print(atheris.path(), end='')")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd
            .output()
            .with_context(|| format!("Couldn't launch {cmd:?}"))?;
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        if !err.is_empty() {
            bail!("Failed to get Atheris path: {}", err);
        }
        atheris_asan_lib = format!("{out}/asan_with_fuzzer.so");
    }

    // Get all crashes.
    let crashes: Vec<_> = fs::read_dir(input_dir)?
        .flatten()
        .map(|p| p.path())
        .filter(|p| p.is_file())
        .map(|p| {
            (
                p.clone(),
                p.file_name().unwrap().to_str().unwrap().to_string(),
            )
        })
        .filter(|(_, fname)| fname.starts_with("crash-") || fname.starts_with("leak-"))
        .collect();

    let jobs = if let Some(jobs) = matches.value_of("jobs") {
        jobs.parse::<usize>().unwrap()
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
    let tool = if atheris_asan_lib.is_empty() {
        "casr-san"
    } else {
        "casr-python"
    };
    custom_pool.install(|| {
        crashes.par_iter().try_for_each(|(crash, fname)| {
            let mut casr_cmd = Command::new(tool);
            casr_cmd.args([
                "-o",
                format!("{}.casrep", output_dir.join(fname).display()).as_str(),
                "--",
            ]);
            if !atheris_asan_lib.is_empty() {
                casr_cmd.arg("python3");
                casr_cmd.env("LD_PRELOAD", &atheris_asan_lib);
            }
            casr_cmd.args(argv.clone());
            casr_cmd.arg(crash);
            debug!("{:?}", casr_cmd);
            let casr_output = casr_cmd
                .output()
                .with_context(|| format!("Couldn't launch {casr_cmd:?}"))?;
            if !casr_output.status.success() {
                let err = String::from_utf8_lossy(&casr_output.stderr);
                if err.contains("Program terminated (no crash)") {
                    warn!("{}: no crash on input {}", tool, crash.display());
                } else {
                    error!("{} for input: {}", err.trim(), crash.display());
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    })?;

    // Deduplicate reports.
    if output_dir.read_dir()?.count() < 2 {
        info!("There are less than 2 CASR reports, nothing to deduplicate.");
        return summarize_results(input_dir, output_dir);
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
        if output_dir
            .read_dir()?
            .flatten()
            .map(|e| e.path())
            .filter(|e| e.extension().is_some() && e.extension().unwrap() == "casrep")
            .count()
            < 2
        {
            info!("There are less than 2 CASR reports, nothing to cluster.");
            return summarize_results(input_dir, output_dir);
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
        for casrep in fs::read_dir(output_dir)?.flatten().map(|e| e.path()) {
            if let Some(ext) = casrep.extension() {
                if ext == "casrep" {
                    let _ = fs::remove_file(casrep);
                }
            }
        }
    }

    summarize_results(input_dir, output_dir)
}

/// Copy crashes next to reports and print summary.
///
/// # Arguments
///
/// `input` - directory containing crashes found by libFuzzer
/// `output` - output directory with triaged reports
fn summarize_results(input: &Path, output: &Path) -> Result<()> {
    // Copy crashes next to reports
    copy_crashes(input, output)?;

    // Print summary
    let status = Command::new("casr-cli")
        .arg(output)
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
/// `input` - directory containing crashes found by libFuzzer
/// `output` - output directory with triaged reports
fn copy_crashes(input: &Path, output: &Path) -> Result<()> {
    for e in fs::read_dir(output)?.flatten().map(|x| x.path()) {
        if e.is_dir() && e.file_name().unwrap().to_str().unwrap().starts_with("cl") {
            copy_crashes(input, &e)?;
        } else if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
            let e = e.with_extension("");
            let _ = fs::copy(input.join(e.file_name().unwrap()), e);
        }
    }

    Ok(())
}
