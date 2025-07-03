use casr::util;
use libcasr::{init_ignored_frames, report::CrashReport, stacktrace::*};

use anyhow::{Result, bail};
use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Arg, ArgAction};
use log::{debug, error, info, warn};
use regex::Regex;
use reqwest::header::{AUTHORIZATION, HeaderMap};
use reqwest::{Client, Method, RequestBuilder, Response, Url};
use walkdir::WalkDir;

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const GET: Method = Method::GET;
const POST: Method = Method::POST;
const CONCURRENCY_LIMIT: usize = 10;

/// HTTP client for sending REST API requests to DefectDojo.
struct DefectDojoClient {
    /// Asynchronous HTTP client.
    client: Client,
    /// DefectDojo API URL.
    api_url: Url,
    /// HTTP headers.
    headers: HeaderMap,
}

/// CASR report hash used for deduplication.
enum ReportHash {
    /// Filtered stack trace hash for ASAN reports.
    Asan(u64),
    /// Crash line string for UBSAN reports.
    Ubsan(String),
}

impl DefectDojoClient {
    /// Construct a new DefectDojo client.
    ///
    /// # Arguments
    ///
    /// * `base_url` - DefectDojo base URL.
    /// * `token` - DefectDojo API key.
    pub fn new(base_url: &Url, token: &str) -> Result<Arc<Self>> {
        let mut client = Self {
            client: Client::new(),
            api_url: base_url.join("api/v2/")?,
            headers: HeaderMap::new(),
        };
        client
            .headers
            .insert(AUTHORIZATION, format!("Token {token}").parse()?);
        Ok(Arc::new(client))
    }

    /// Start building request to DefectDojo API.
    ///
    /// # Arguments
    ///
    /// * `method` - request method (GET, POST, etc.).
    /// * `url` - DefectDojo API URL (findings/, products/, etc.).
    pub fn request(&self, method: Method, url: &str) -> Result<RequestBuilder> {
        Ok(self
            .client
            .request(method, self.api_url.join(url)?)
            .headers(self.headers.clone()))
    }

    /// Get DefectDojo entity if it exists, or create a new one.
    ///
    /// # Arguments
    ///
    /// * `toml` - TOML with parameters for entity.
    /// * `entity_name` - entity name (product, engagement, test, test_type).
    ///
    /// # Return value
    ///
    /// Entity id.
    pub async fn get_or_create_entity(&self, toml: &toml::Table, entity_name: &str) -> Result<i64> {
        let url = format!("{entity_name}s/");
        let query = match entity_name {
            "product" => vec![("name_exact", toml["name"].as_str().unwrap().to_string())],
            "engagement" => vec![
                ("name", toml["name"].as_str().unwrap().to_string()),
                ("product", toml["product"].as_integer().unwrap().to_string()),
            ],
            "test" => vec![
                (
                    "test_type",
                    toml["test_type"].as_integer().unwrap().to_string(),
                ),
                (
                    "engagement",
                    toml["engagement"].as_integer().unwrap().to_string(),
                ),
            ],
            // test_type
            _ => vec![("name", toml["name"].as_str().unwrap().to_string())],
        };

        // Get existing entity.
        info!("Trying to find existing {entity_name}");
        let response = self.request(GET, &url)?.query(&query).send().await?;
        let results = get_results(response).await?;
        if !results.is_empty() {
            let id = get_result_id(&results[0])?;
            info!("Found existing {entity_name} with id={id}");
            return Ok(id);
        }

        // Create new entity.
        info!("Didn't find {entity_name} - creating a new one");
        let response = self.request(POST, &url)?.json(toml).send().await?;
        if let Err(e) = response.error_for_status_ref() {
            error!("{}", response.text().await?);
            bail!("{e}");
        }
        let json: serde_json::Value = response.json().await?;
        let id = get_result_id(&json)?;
        info!("Created new {entity_name} with id={id}");
        Ok(id)
    }

    /// Download CASR report for finding and return its hash.
    ///
    /// # Arguments
    ///
    /// * `id` - finding id.
    pub async fn get_finding_hash(&self, id: i64) -> Result<Option<ReportHash>> {
        let url = format!("findings/{id}/files/");
        let response = self.request(GET, &url)?.send().await?;
        if let Err(e) = response.error_for_status_ref() {
            error!("{}", response.text().await?);
            bail!("{}", e);
        }
        let json: serde_json::Value = response.json().await?;
        let Some(obj) = json.as_object() else {
            bail!("Failed to get JSON object for DefectDojo response");
        };
        if !obj.contains_key("files") || !obj["files"].is_array() {
            bail!("Failed to get files from DefectDojo JSON response");
        }
        for file in obj["files"].as_array().unwrap() {
            let Some(file) = file.as_object() else {
                bail!("Failed to get JSON object for file");
            };
            if !file.contains_key("title") || !file["title"].is_string() {
                bail!("Failed to get file title");
            }
            if file["title"].as_str().unwrap().starts_with("CASR (") {
                if !file.contains_key("id") || !file["id"].is_i64() {
                    bail!("Failed to get file id");
                }
                let file_id = file["id"].as_i64().unwrap();
                let file_url = format!("{url}download/{file_id}/");
                let response = self.request(GET, &file_url)?.send().await?;
                if let Err(e) = response.error_for_status_ref() {
                    error!("{}", response.text().await?);
                    bail!("{e}");
                }
                let report = response.json::<CrashReport>().await;
                if let Err(e) = report {
                    error!("Failed to parse CASR report {file_url}: {e}");
                    return Ok(None);
                }
                let hash = compute_report_hash(&report.unwrap(), &file_url);
                if let Err(e) = hash {
                    error!("{e}");
                    return Ok(None);
                }
                return Ok(Some(hash.unwrap()));
            }
        }
        Ok(None)
    }

    /// Upload file for DefectDojo finding.
    ///
    /// # Arguments
    ///
    /// * `path` - file path (e.g., /tmp/file.casrep).
    /// * `ext` - new file extension for DefectDojo upload (e.g., casrep.json).
    /// * `title` - file title (e.g., CASR).
    /// * `id` - DefectDojo finding id.
    async fn upload_file(&self, path: &PathBuf, ext: &str, title: &str, id: i64) -> Result<()> {
        let url = format!("findings/{id}/files/");
        let fname = Path::new(path.file_name().unwrap()).with_extension(ext);
        let file = reqwest::multipart::Part::bytes(fs::read(path)?)
            .file_name(fname.to_str().unwrap().to_string());
        let form = reqwest::multipart::Form::new()
            .text("title", format!("{title} (finding {id})"))
            .part("file", file);
        let response = self.request(POST, &url)?.multipart(form).send().await?;
        if let Err(e) = response.error_for_status_ref() {
            error!("{}", response.text().await?);
            bail!("{e}");
        }
        Ok(())
    }

    /// Upload finding to DefectDojo.
    ///
    /// # Arguments
    ///
    /// * `path` - CASR report file path.
    /// * `report` - CASR report.
    /// * `gdb` - additional CASR report from GDB.
    /// * `extra_gdb_report` - when true, print "No crash" if `gdb` is None.
    /// * `product_name` - DefectDojo product name.
    /// * `test_id` - DefectDojo test id.
    pub async fn upload_finding(
        &self,
        path: PathBuf,
        report: CrashReport,
        gdb: Option<CrashReport>,
        extra_gdb_report: bool,
        product_name: String,
        test_id: i64,
    ) -> Result<()> {
        // Create new finding.
        let mut executable = "";
        if let Some(fname) = Path::new(&report.executable_path).file_name() {
            executable = fname.to_str().unwrap();
        }
        let mut title = format!(
            "[{product_name}] [{executable}] {} in {}",
            report.execution_class.short_description, report.crashline
        );
        title.truncate(500);
        let (num_severity, severity) = match report.execution_class.severity.as_str() {
            "EXPLOITABLE" => ("S0", "Critical"),
            "PROBABLY_EXPLOITABLE" => ("S1", "High"),
            "NOT_EXPLOITABLE" => {
                if report.ubsan_report.is_empty() {
                    ("S2", "Medium")
                } else {
                    ("S3", "Low")
                }
            }
            _ => ("S3", "Low"),
        };
        let mut finding = serde_json::Map::new();
        finding.insert(
            "title".to_string(),
            serde_json::Value::String(title.clone()),
        );
        finding.insert("active".to_string(), serde_json::Value::Bool(true));
        finding.insert("verified".to_string(), serde_json::Value::Bool(false));
        // FIXME: DefectDojo still thinks it is a static finding and ignores the
        // following fields.
        finding.insert("static_finding".to_string(), serde_json::Value::Bool(false));
        finding.insert("dynamic_finding".to_string(), serde_json::Value::Bool(true));
        finding.insert(
            "test".to_string(),
            serde_json::Value::Number(test_id.into()),
        );
        finding.insert(
            "numerical_severity".to_string(),
            serde_json::Value::String(num_severity.to_string()),
        );
        finding.insert(
            "severity".to_string(),
            serde_json::Value::String(severity.to_string()),
        );
        let mut reproduce = report.proc_cmdline.clone();
        if !report.stdin.is_empty() {
            reproduce += &format!(" < {}", report.stdin);
        }

        let security_re =
            Regex::new("null_deref|out_of_bounds|int_overflow|div_by_zero|neg_size|num_trunc")
                .unwrap();
        if security_re.is_match(&reproduce) {
            finding.insert(
                "tags".to_string(),
                serde_json::Value::Array(vec![serde_json::Value::String(
                    "sydr-security".to_string(),
                )]),
            );
        }

        finding.insert(
            "steps_to_reproduce".to_string(),
            serde_json::Value::String(reproduce),
        );
        let crash_line: Vec<&str> = report.crashline.split(':').collect();
        finding.insert(
            "file_path".to_string(),
            serde_json::Value::String(crash_line[0].to_string()),
        );
        if let Some(line) = crash_line.get(1) {
            finding.insert(
                "line".to_string(),
                serde_json::Value::Number(line.parse::<i32>()?.into()),
            );
        }
        finding.insert(
            "found_by".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::Number(1.into())]),
        );
        let Some(date) = report.date.split('T').next() else {
            bail!(
                "Failed to parse date {} for CASR report {}",
                report.date,
                path.display()
            );
        };
        finding.insert(
            "date".to_string(),
            serde_json::Value::String(date.to_string()),
        );
        finding.insert(
            "description".to_string(),
            serde_json::Value::String(get_report_description(&report, &gdb, extra_gdb_report)),
        );
        let response = self
            .request(POST, "findings/")?
            .json(&finding)
            .send()
            .await?;
        if let Err(e) = response.error_for_status_ref() {
            error!("{}", response.text().await?);
            bail!("{}", e);
        }
        let response: serde_json::Value = response.json().await?;
        let id = get_result_id(&response)?;
        debug!("Created new finding '{title}' with id={id}");

        // Upload CASR report.
        self.upload_file(&path, "casrep.json", "CASR", id).await?;
        debug!("Uploaded CASR report for finding '{title}' with id={id}");

        // Upload additional CASR report from GDB.
        if gdb.is_some() {
            self.upload_file(
                &path.with_extension("gdb.casrep"),
                "casrep.json",
                "CASR GDB",
                id,
            )
            .await?;
            debug!("Uploaded CASR GDB report for finding '{title}' with id={id}");
        }

        // Upload crash seed.
        let mut crash_path = path.with_extension("");
        if let Some(ext) = crash_path.extension()
            && ext == "gdb"
        {
            crash_path = crash_path.with_extension("");
        }

        if crash_path.exists() {
            self.upload_file(&crash_path, ".txt", "Crash seed", id)
                .await?;
            debug!("Uploaded crash seed for finding '{title}' with id={id}");
        }

        Ok(())
    }
}

/// Return JSONs for the results of DefectDojo query.
///
/// # Arguments
///
/// * `response` - HTTP response.
async fn get_results(response: Response) -> Result<Vec<serde_json::Value>> {
    if let Err(e) = response.error_for_status_ref() {
        error!("{}", response.text().await?);
        bail!("{}", e);
    }
    let mut json: serde_json::Value = response.json().await?;
    let Some(obj) = json.as_object_mut() else {
        bail!("Failed to get JSON object for DefectDojo response");
    };
    if !obj.contains_key("count") || !obj["count"].is_u64() {
        bail!("Failed to get results count from DefectDojo JSON response");
    }
    if obj["count"].as_u64().unwrap() == 0 {
        return Ok(Vec::new());
    }
    if !obj.contains_key("results")
        || !obj["results"].is_array()
        || obj["results"].as_array().unwrap().is_empty()
    {
        bail!("Failed to get results from DefectDojo JSON response");
    }
    let serde_json::Value::Array(a) = obj["results"].take() else {
        unreachable!();
    };
    Ok(a)
}

/// Return id for DefectDojo JSON result.
///
/// # Arguments
///
/// * `result` - DefectDojo JSON result.
fn get_result_id(result: &serde_json::Value) -> Result<i64> {
    let Some(obj) = result.as_object() else {
        bail!("Failed to get JSON object for DefectDojo result");
    };
    if !obj.contains_key("id") || !obj["id"].is_i64() {
        bail!("Failed to get id from DefectDojo JSON result");
    }
    Ok(result["id"].as_i64().unwrap())
}

/// Return ids for the results of DefectDojo query.
///
/// # Arguments
///
/// * `response` - HTTP response.
async fn get_results_ids(response: Response) -> Result<Vec<i64>> {
    get_results(response)
        .await?
        .iter()
        .map(get_result_id)
        .collect()
}

/// Return findings ids for DefectDojo query.
///
/// # Arguments
///
/// * `request` - HTTP request that gets findings.
async fn get_findings_ids(request: RequestBuilder) -> Result<Vec<i64>> {
    get_results_ids(request.send().await?).await
}

/// Return hash for CASR report.
///
/// Return crash line string for UBSAN report, and filtered stack trace hash for
/// other report type (e.g., ASAN).
///
/// # Arguments
///
/// * `report` - CASR report.
/// * `name` - CASR report name.
fn compute_report_hash(report: &CrashReport, name: &str) -> Result<ReportHash> {
    if !report.ubsan_report.is_empty() {
        if report.crashline.is_empty() {
            bail!("Empty crash line for CASR report {}", name);
        }
        let crash_line: Vec<&str> = report.crashline.split(':').collect();
        if crash_line.len() < 2 {
            warn!(
                "Crash line for CASR report {} does not have a line number: {}",
                name, report.crashline
            );
            return Ok(ReportHash::Ubsan(report.crashline.clone()));
        }
        return Ok(ReportHash::Ubsan(crash_line[..2].join(":")));
    }
    if report.stacktrace.is_empty() {
        bail!("Empty stack trace for CASR report {}", name);
    }
    let stacktrace = report.filtered_stacktrace();
    if let Err(e) = stacktrace {
        bail!(
            "Failed to parse stack trace for CASR report {}: {}",
            name,
            e
        );
    }
    let mut hasher = DefaultHasher::new();
    stacktrace.unwrap().hash(&mut hasher);
    Ok(ReportHash::Asan(hasher.finish()))
}

/// Return CASR report description to be saved in DefectDojo finding.
///
/// # Arguments
///
/// * `report` - CASR report.
/// * `gdb` - additional CASR report from GDB.
/// * `extra_gdb_report` - when true, print "No crash" if `gdb` is None.
fn get_report_description(
    report: &CrashReport,
    gdb: &Option<CrashReport>,
    extra_gdb_report: bool,
) -> String {
    let mut d = format!("**Crash line:** {}\n", report.crashline);
    let e = &report.execution_class;
    d += &format!(
        "**Severity:** {}: {}: {}\n{}\n",
        e.severity, e.short_description, e.description, e.explanation
    );
    if let Some(gdb_report) = gdb {
        let e = &gdb_report.execution_class;
        d += &format!(
            "**GDB severity (without ASAN):** {}: {}: {}\n{}\n",
            e.severity, e.short_description, e.description, e.explanation
        );
    } else if extra_gdb_report && report.ubsan_report.is_empty() {
        d += "**GDB severity (without ASAN):** No crash\n";
    }
    d += &format!("**Command:** {}", report.proc_cmdline);
    if !report.stdin.is_empty() {
        d += &format!(" < {}", report.stdin);
    }
    d += &format!(
        "\n**OS:** {} {}\n**Architecture:** {}\n\n",
        report.os, report.os_release, report.architecture
    );
    if !report.source.is_empty() {
        d += "# Source\n\n```\n";
        d += &report.source.join("\n");
        d += "\n```\n\n";
    }
    if !report.asan_report.is_empty() {
        d += "# ASAN report\n\n```\n";
        d += &report.asan_report.join("\n");
        d += "\n```\n\n";
    }
    if !report.ubsan_report.is_empty() {
        d += "# UBSAN report\n\n```\n";
        d += &report.ubsan_report.join("\n");
        d += "\n```\n\n";
    }
    if !report.python_report.is_empty() {
        d += "# Python report\n\n```\n";
        d += &report.python_report.join("\n");
        d += "\n```\n\n";
    }
    if !report.go_report.is_empty() {
        d += "# Go report\n\n```\n";
        d += &report.go_report.join("\n");
        d += "\n```\n\n";
    }
    if !report.rust_report.is_empty() {
        d += "# Rust report\n\n```\n";
        d += &report.rust_report.join("\n");
        d += "\n```\n\n";
    }
    d += "# Stack trace\n\n```\n";
    d += &report.stacktrace.join("\n");
    d += "\n```\n\n# Environment variables\n\n```\n";
    d += &report.proc_environ.join("\n");
    d += "\n```\n";
    d
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let options = clap::Command::new("casr-dojo")
        .version(clap::crate_version!())
        .about("Tool for uploading new and unique CASR reports to DefectDojo")
        .term_width(90)
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .short('l')
                .action(ArgAction::Set)
                .default_value("info")
                .value_parser(["info", "debug"])
                .help("Logging level"),
        )
        .arg(
            Arg::new("url")
                .long("url")
                .short('u')
                .action(ArgAction::Set)
                .value_name("URL")
                .required(true)
                .help("DefectDojo base URL")
                .value_parser(Url::parse),
        )
        .arg(
            Arg::new("token")
                .long("token")
                .short('t')
                .action(ArgAction::Set)
                .value_name("TOKEN")
                .required(true)
                .help("DefectDojo API key"),
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .action(ArgAction::Set)
                .value_name("INPUT_DIR")
                .required(true)
                .help("Directory that is recursively searched for CASR reports (also, crash seeds and CASR GDB reports if they are present)")
                .value_parser(move |arg: &str| {
                    let i_dir = Path::new(arg);
                    if !i_dir.exists() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(
                            ContextKind::InvalidValue,
                            ContextValue::String(
                                "Directory with CASR reports doesn't exist.".to_owned(),
                            ),
                        );
                        return Err(err);
                    }
                    if !i_dir.is_dir() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(
                            ContextKind::InvalidValue,
                            ContextValue::String("Input path should be a directory.".to_owned()),
                        );
                        return Err(err);
                    }
                    Ok(i_dir.to_owned())
                }),
        )
        .arg(
            Arg::new("params")
                .action(ArgAction::Set)
                .required(true)
                .value_name("PARAMS")
                .value_parser(clap::value_parser!(PathBuf))
                .help("TOML file with parameters for DefectDojo product, engagement, and test"),
        )
        .get_matches();

    // Init stack trace filtering.
    init_ignored_frames!("cpp", "rust", "python", "go");

    // Init log.
    util::initialize_logging(&options);

    // Get new CASR reports.
    let mut new_casr_reports: Vec<(PathBuf, CrashReport)> =
        WalkDir::new(options.get_one::<PathBuf>("input").unwrap())
            .into_iter()
            .flatten()
            .map(|e| e.into_path())
            .filter(|e| e.is_file())
            .filter(|e| e.parent().unwrap().file_name().unwrap() != "clerr")
            .filter(|e| e.extension().is_some() && e.extension().unwrap() == "casrep")
            .filter(|e| {
                !e.to_str().unwrap().ends_with(".gdb.casrep")
                    || !e.with_extension("").with_extension("casrep").exists()
            })
            .map(|e| {
                let r = util::report_from_file(e.as_path())?;
                Ok((e, r))
            })
            .collect::<Result<Vec<_>>>()?;
    new_casr_reports.sort_by(|(e1, _), (e2, _)| e1.cmp(e2));

    // Create DefectDojo client.
    let client = DefectDojoClient::new(
        options.get_one::<Url>("url").unwrap(),
        options.get_one::<String>("token").unwrap(),
    )?;

    // Parse product, engagement, and test parameters.
    let mut toml = fs::read_to_string(options.get_one::<PathBuf>("params").unwrap())?
        .parse::<toml::Table>()?;

    // Check for required parameters.
    if !toml.contains_key("product")
        || !toml.contains_key("engagement")
        || !toml["product"].is_table()
        || !toml["engagement"].is_table()
    {
        bail!("[product] and [engagement] tables must be specified in TOML");
    }
    if !toml["product"].as_table().unwrap().contains_key("name")
        || !toml["product"].as_table().unwrap()["name"].is_str()
    {
        bail!("[product] name (string) must be specified in TOML");
    }
    if !toml["engagement"].as_table().unwrap().contains_key("name")
        || !toml["engagement"].as_table().unwrap()["name"].is_str()
    {
        bail!("[engagement] name (string) must be specified in TOML");
    }
    if toml.contains_key("test") {
        let Some(test) = toml["test"].as_table() else {
            bail!("[test] must be a table");
        };
        if test.contains_key("test_type")
            && !test["test_type"].is_integer()
            && !test["test_type"].is_str()
        {
            bail!("[test] test_type must be integer or string");
        }
    } else {
        toml.insert("test".to_string(), toml::Value::Table(toml::Table::new()));
    }

    // Fill default parameters.
    {
        let product = toml["product"].as_table_mut().unwrap();
        if !product.contains_key("description") {
            product.insert("description".to_string(), product["name"].clone());
        }
        if !product.contains_key("prod_type") {
            product.insert("prod_type".to_string(), toml::Value::Integer(1)); // RnD
        }
    }
    {
        let engagement = toml["engagement"].as_table_mut().unwrap();
        if !engagement.contains_key("target_end") {
            engagement.insert(
                "target_end".to_string(),
                toml::Value::String(chrono::Local::now().format("%Y-%m-%d").to_string()),
            );
        }
        if !engagement.contains_key("target_start") {
            engagement.insert("target_start".to_string(), engagement["target_end"].clone());
        }
        if !engagement.contains_key("engagement_type") {
            engagement.insert(
                "engagement_type".to_string(),
                toml::Value::String("CI/CD".to_string()),
            );
        }
    }
    {
        let target_start = toml["engagement"].as_table().unwrap()["target_start"].clone();
        let target_end = toml["engagement"].as_table().unwrap()["target_end"].clone();
        let test = toml["test"].as_table_mut().unwrap();
        if !test.contains_key("test_type") {
            test.insert(
                "test_type".to_string(),
                toml::Value::String("CASR Crash Reports".to_string()),
            );
        }
        if !test.contains_key("target_end") {
            test.insert("target_end".to_string(), target_end);
        }
        if !test.contains_key("target_start") {
            test.insert("target_start".to_string(), target_start);
        }
        if !test.contains_key("environment") {
            test.insert("environment".to_string(), toml::Value::Integer(3)); // Production
        }
    }

    // Get product.
    let product_id;
    {
        let product = toml["product"].as_table().unwrap();
        info!(
            "Getting product id for {}",
            product["name"].as_str().unwrap()
        );
        product_id = client.get_or_create_entity(product, "product").await?;
    }

    // Get engagement.
    let engagement_id;
    {
        let engagement = toml["engagement"].as_table_mut().unwrap();
        engagement.insert("product".to_string(), toml::Value::Integer(product_id));
        info!(
            "Getting id for engagement '{}'",
            engagement["name"].as_str().unwrap()
        );
        engagement_id = client
            .get_or_create_entity(engagement, "engagement")
            .await?;
    }

    // Get test.
    let test_id;
    {
        let test = toml["test"].as_table_mut().unwrap();
        test.insert(
            "engagement".to_string(),
            toml::Value::Integer(engagement_id),
        );
        if let Some(test_type_name) = test["test_type"].as_str() {
            // Get test type.
            let mut test_type = toml::Table::new();
            test_type.insert(
                "name".to_string(),
                toml::Value::String(test_type_name.to_string()),
            );
            test_type.insert("dynamic_tool".to_string(), toml::Value::Boolean(true));
            info!("Getting id for test type '{test_type_name}'");
            let test_type_id = client.get_or_create_entity(&test_type, "test_type").await?;
            test.insert("test_type".to_string(), toml::Value::Integer(test_type_id));
        }
        info!("Getting test id");
        test_id = client.get_or_create_entity(test, "test").await?;
    }

    let product_name = toml["product"].as_table().unwrap()["name"]
        .as_str()
        .unwrap()
        .to_string();

    // Get all active findings for product.
    let active = client.request(GET, "findings/")?.query(&[
        ("product_name", product_name.as_str()),
        ("active", "true"),
        ("limit", "100000"),
    ]);

    // Get all false positive non-active findings for product.
    let false_p = client.request(GET, "findings/")?.query(&[
        ("product_name", product_name.as_str()),
        ("active", "false"),
        ("false_p", "true"),
        ("limit", "100000"),
    ]);

    // Get all out of scope non-active findings for product.
    let out_of_scope = client.request(GET, "findings/")?.query(&[
        ("product_name", product_name.as_str()),
        ("active", "false"),
        ("out_of_scope", "true"),
        ("limit", "100000"),
    ]);

    // Wait for findings responses.
    info!("Getting all active, false positive, and out of scope findings for {product_name}");
    let mut findings = Vec::new();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move { get_findings_ids(active).await });
    tasks.spawn(async move { get_findings_ids(false_p).await });
    tasks.spawn(async move { get_findings_ids(out_of_scope).await });
    while let Some(r) = tasks.join_next().await {
        findings.append(&mut r??);
    }

    info!("Getting CASR reports for findings and computing stack trace hashes");
    let mut casr_asan_hash = HashSet::new();
    let mut casr_ubsan_hash = HashSet::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut findings = findings.into_iter();
    loop {
        while tasks.len() < CONCURRENCY_LIMIT {
            let Some(f) = findings.next() else {
                break;
            };
            let c = Arc::clone(&client);
            tasks.spawn(async move { c.get_finding_hash(f).await });
        }
        let Some(r) = tasks.join_next().await else {
            break;
        };
        if let Some(hash) = r?? {
            match hash {
                ReportHash::Asan(h) => casr_asan_hash.insert(h),
                ReportHash::Ubsan(h) => casr_ubsan_hash.insert(h),
            };
        }
    }

    // Skip duplicate new CASR reports and parse additional GDB reports for unique ones.
    let total_reports_cnt = new_casr_reports.len();
    let new_casr_reports: Vec<(PathBuf, CrashReport, ReportHash)> = new_casr_reports
        .into_iter()
        .map(|(e, report)| {
            let hash = compute_report_hash(&report, e.to_str().unwrap())?;
            Ok((e, report, hash))
        })
        .collect::<Result<Vec<_>>>()?;
    let new_casr_reports: Vec<(PathBuf, CrashReport, Option<CrashReport>)> = new_casr_reports
        .into_iter()
        .filter(|(_, _, hash)| match hash {
            ReportHash::Asan(h) => casr_asan_hash.insert(*h),
            ReportHash::Ubsan(h) => casr_ubsan_hash.insert(h.to_string()),
        })
        .map(|(e, report, _)| {
            let gdb = e.with_extension("gdb.casrep");
            let gdb = if gdb.exists() {
                Some(util::report_from_file(gdb.as_path())?)
            } else {
                None
            };
            Ok((e, report, gdb))
        })
        .collect::<Result<Vec<_>>>()?;
    info!(
        "{} new reports are duplicate",
        total_reports_cnt - new_casr_reports.len()
    );

    info!(
        "Uploading {} new unique CASR reports to DefectDojo",
        new_casr_reports.len()
    );
    let extra_gdb_report = new_casr_reports.iter().any(|(_, _, gdb)| gdb.is_some());
    let mut tasks = tokio::task::JoinSet::new();
    let mut new_casr_reports = new_casr_reports.into_iter();
    loop {
        while tasks.len() < CONCURRENCY_LIMIT {
            let Some((path, report, gdb)) = new_casr_reports.next() else {
                break;
            };
            let c = Arc::clone(&client);
            let pname = product_name.clone();
            tasks.spawn(async move {
                c.upload_finding(path, report, gdb, extra_gdb_report, pname, test_id)
                    .await
            });
        }
        let Some(r) = tasks.join_next().await else {
            break;
        };
        if let Err(e) = r? {
            error!("{e}");
        }
    }

    Ok(())
}
