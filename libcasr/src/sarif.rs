//! Sarif module contains `Sarif` struct that contains multiple `CrashReport`
//! structs in SARIF format.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::execution_class::{ExecutionClass, CLASSES};
use crate::init_ignored_frames;
use crate::report::CrashReport;
use crate::stacktrace::{STACK_FRAME_FILEPATH_IGNORE_REGEXES, STACK_FRAME_FUNCTION_IGNORE_REGEXES};

use serde_json::{Map, Value};

use std::path::{Path, PathBuf};

use lexiclean::Lexiclean;

/// CASR CrashReports in SARIF format.
#[derive(Clone, Debug, Default)]
pub struct SarifReport {
    /// SARIF json.
    pub json: Value,
    /// current rule id for generated ExecutionClasses.
    current_id: u64,
}

impl SarifReport {
    /// Create new `SarifReport` with blank required fields
    pub fn new() -> Self {
        let mut map = Map::new();
        map.insert(
            "$schema".to_string(),
            Value::String("https://json.schemastore.org/sarif-2.1.0.json".to_string()),
        );
        map.insert("version".to_string(), Value::String("2.1.0".to_string()));
        let mut runs = Vec::new();
        let mut run = Map::new();
        let mut tool = Map::new();
        let mut driver = Map::new();
        driver.insert("name".to_string(), Value::String("CASR".to_string()));
        driver.insert("rules".to_string(), Value::Array(Vec::new()));
        tool.insert("driver".to_string(), Value::Object(driver));
        run.insert("tool".to_string(), Value::Object(tool));
        run.insert("results".to_string(), Value::Array(Vec::new()));
        runs.push(Value::Object(run));
        map.insert("runs".to_string(), Value::Array(runs));
        Self {
            json: Value::Object(map),
            current_id: 0,
        }
    }

    /// Set name for SARIF tool:driver.
    /// NOTE: before use this method,
    /// use SarifReport::new() to get report.
    ///
    ///  # Arguments
    ///
    ///  * 'name' - tool:driver name (default is CASR)
    pub fn set_name(&mut self, name: &str) {
        let driver = self.json.as_object_mut().unwrap()["runs"]
            .as_array_mut()
            .unwrap()[0]
            .as_object_mut()
            .unwrap()["tool"]
            .as_object_mut()
            .unwrap()["driver"]
            .as_object_mut()
            .unwrap();
        driver.insert("name".to_string(), Value::String(name.to_string()));
    }

    /// SARIF rule from ExecutionClass.
    /// NOTE: before using this method,
    /// use SarifReport::new() to get report.
    ///
    ///  # Arguments
    ///
    ///  * 'class' - ExecutionClass from CrashReport
    ///
    ///  # Return
    ///
    ///  If Rule is new, than it's json object is returned and ruleId
    ///  else ruleId only is returned.
    fn rule(&self, class: &ExecutionClass) -> (Option<Value>, String) {
        let rule_id = if let Some(pos) = CLASSES
            .iter()
            .position(|item| item.1 == class.short_description)
        {
            format!("F{:0>2}", pos)
        } else {
            let s = format!("G{}", self.current_id);
            s
        };

        let rules = self.json.as_object().unwrap()["runs"].as_array().unwrap()[0]
            .as_object()
            .unwrap()["tool"]
            .as_object()
            .unwrap()["driver"]
            .as_object()
            .unwrap()["rules"]
            .as_array()
            .unwrap();
        if rules
            .iter()
            .any(|r| r.as_object().unwrap()["name"].as_str().unwrap() == class.short_description)
        {
            // ExecutionClass is already added.
            return (None, rule_id);
        }
        let mut rule = Map::new();
        rule.insert("id".to_string(), Value::String(rule_id.clone()));
        rule.insert(
            "name".to_string(),
            Value::String(class.short_description.clone()),
        );
        let mut short_desc = Map::new();
        short_desc.insert("text".to_string(), Value::String(class.description.clone()));
        rule.insert(
            "shortDescription".to_string(),
            Value::Object(short_desc.clone()),
        );
        let mut full_desc = Map::new();
        full_desc.insert("text".to_string(), Value::String(class.explanation.clone()));
        rule.insert(
            "fullDescription".to_string(),
            Value::Object(full_desc.clone()),
        );
        let mut properties = Map::new();
        let severity = if class.short_description == "SegFaultOnPc"
            || class.short_description == "ReturnAv"
            || class.short_description == "BranchAv"
            || class.short_description == "CallAv"
        {
            "9.0".to_string()
        } else {
            match class.severity.as_str() {
                "EXPLOITABLE" => "8.0".to_string(),
                "PROBABLY_EXPLOITABLE" => "6.0".to_string(),
                _ => "3.0".to_string(),
            }
        };
        properties.insert("security-severity".to_string(), Value::String(severity));
        rule.insert("properties".to_string(), Value::Object(properties));

        (Some(Value::Object(rule)), rule_id)
    }

    /// Add CASR CrashReport to SARIF report.
    /// NOTE: before using this method,
    /// use SarifReport::new() to get report.
    ///
    ///  # Arguments
    ///
    ///  * 'report' - CrashReport
    ///
    ///  * 'source_root' - Path to source root directory.
    pub fn add_casr_report<T: AsRef<Path>>(
        &mut self,
        report: &CrashReport,
        source_root: T,
    ) -> Result<()> {
        let (rule, rule_id) = self.rule(&report.execution_class);
        if let Some(rule) = rule {
            let rules = self.json.as_object_mut().unwrap()["runs"]
                .as_array_mut()
                .unwrap()[0]
                .as_object_mut()
                .unwrap()["tool"]
                .as_object_mut()
                .unwrap()["driver"]
                .as_object_mut()
                .unwrap()["rules"]
                .as_array_mut()
                .unwrap();
            rules.push(rule);
            if rule_id.starts_with('G') {
                self.current_id += 1;
            }
        }

        let results = self.json.as_object_mut().unwrap()["runs"]
            .as_array_mut()
            .unwrap()[0]
            .as_object_mut()
            .unwrap()["results"]
            .as_array_mut()
            .unwrap();
        let mut result = Map::new();
        result.insert("ruleId".to_string(), Value::String(rule_id));
        result.insert("level".to_string(), Value::String("error".to_string()));
        let mut message = Map::new();
        let text = if !report.stdin.is_empty() {
            format!(
                "{}: {} < {}",
                report.execution_class.short_description, report.proc_cmdline, report.stdin
            )
        } else {
            format!(
                "{}: {}",
                report.execution_class.short_description, report.proc_cmdline
            )
        };
        message.insert("text".to_string(), Value::String(text));
        result.insert("message".to_string(), Value::Object(message));
        let mut locations: Vec<Value> = Vec::new();
        let mut location = Map::new();
        let mut physical_loc = Map::new();
        let mut artifact_loc = Map::new();
        let mut region = Map::new();
        let parts: Vec<_> = report.crashline.split(':').map(|s| s.to_string()).collect();
        if parts.len() != 2 && parts.len() != 3 {
            return Err(Error::Casr(format!(
                "Unable to parse crashline: {}",
                report.crashline
            )));
        }

        let norm_source_path = normalize_path(&parts[0], source_root.as_ref());

        artifact_loc.insert(
            "uri".to_string(),
            Value::String(norm_source_path.display().to_string()),
        );
        artifact_loc.insert(
            "uriBaseId".to_string(),
            Value::String("%SRCROOT%".to_string()),
        );
        physical_loc.insert("artifactLocation".to_string(), Value::Object(artifact_loc));
        let Ok(line) = parts[1].parse::<u32>() else {
            return Err(Error::Casr(format!(
                "Unable to extract line number from crashline: {}",
                report.crashline
            )));
        };
        region.insert("startLine".to_string(), Value::Number(line.into()));
        if parts.len() == 3 {
            let Ok(column) = parts[2].parse::<u32>() else {
                return Err(Error::Casr(format!(
                    "Unable to extract column number from crashline: {}",
                    report.crashline
                )));
            };

            region.insert("startColumn".to_string(), Value::Number(column.into()));
        }
        physical_loc.insert("region".to_string(), Value::Object(region));
        location.insert("physicalLocation".to_string(), Value::Object(physical_loc));
        locations.push(Value::Object(location));

        result.insert("locations".to_string(), Value::Array(locations));

        let mut stacks: Vec<Value> = Vec::new();
        let mut stack = Map::new();
        let mut frames: Vec<Value> = Vec::new();
        init_ignored_frames!("cpp", "rust", "python", "go", "java");
        let stacktrace = report.filtered_stacktrace()?;
        for (n, entry) in stacktrace.iter().enumerate() {
            let mut frame = Map::new();
            let mut msg = Map::new();
            let mut location = Map::new();
            let mut physical_loc = Map::new();
            let mut artifact_loc = Map::new();
            let mut region = Map::new();

            if entry.debug.file.is_empty() || entry.debug.line == 0 {
                continue;
            }

            let norm_source_path = normalize_path(&entry.debug.file, source_root.as_ref());
            artifact_loc.insert(
                "uri".to_string(),
                Value::String(norm_source_path.display().to_string()),
            );
            artifact_loc.insert(
                "uriBaseId".to_string(),
                Value::String("%SRCROOT%".to_string()),
            );
            physical_loc.insert("artifactLocation".to_string(), Value::Object(artifact_loc));
            region.insert(
                "startLine".to_string(),
                Value::Number(entry.debug.line.into()),
            );
            if entry.debug.column != 0 {
                region.insert(
                    "startColumn".to_string(),
                    Value::Number(entry.debug.column.into()),
                );
            }
            physical_loc.insert("region".to_string(), Value::Object(region));
            location.insert("physicalLocation".to_string(), Value::Object(physical_loc));
            let frame_info = format!("#{} {}", n, entry.function);
            msg.insert("text".to_string(), Value::String(frame_info));
            location.insert("message".to_string(), Value::Object(msg));
            frame.insert("location".to_string(), Value::Object(location));
            frames.push(Value::Object(frame));
        }

        stack.insert("frames".to_string(), Value::Array(frames));
        let mut msg = Map::new();
        msg.insert("text".to_string(), Value::String("Stacktrace".to_string()));
        stack.insert("message".to_string(), Value::Object(msg));
        stacks.push(Value::Object(stack));
        result.insert("stacks".to_string(), Value::Array(stacks));
        results.push(Value::Object(result));
        Ok(())
    }
}

///  Remove source root path prefix
///  form source path
///
///  # Arguments
///
///  * 'path' - Path to source file
///
///  * 'root' - Path to root directory with source files
///
///  # Return
///
///  If success returns normalized source path, else original source path is returned.
fn normalize_path<P>(path: P, root: &Path) -> PathBuf
where
    P: AsRef<Path>,
{
    if let Ok(norm_source_path) = path.as_ref().lexiclean().as_path().strip_prefix(root) {
        norm_source_path.to_path_buf()
    } else {
        path.as_ref().lexiclean()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif() {
        let mut sarif = SarifReport::new();
        let data = "{\n\
            \"ProcCmdline\": \"/home/avgor46/test_threads_casr/xlnt/load_sydr /home/avgor46/test_threads_casr/xlnt/out/crashes/crash-b15d6963751a2d36f401d36abaaba7e1874f6f63\",\n\
            \"CrashSeverity\": {\n\
                \"Type\": \"NOT_EXPLOITABLE\",\n\
                \"ShortDescription\": \"SourceAv\",\n\
                \"Description\": \"Access violation on source operand\",\n\
                \"Explanation\": \"The target crashed on an access violation at an address matching the source operand of the current instruction. This likely indicates a read access violation.\"\n\
            },\n\
            \"Stacktrace\": [\n\
                \"#0  0x00000000005e3099 in xlnt::detail::compound_document::read_directory (this=0x7fffffffcee0) at /xlnt/source/detail/cryptography/compound_document.cpp:975\",\n\
                \"#1  0x00000000005e2956 in xlnt::detail::compound_document::compound_document (this=0x7fffffffcee0, in=...) at /xlnt/source/detail/cryptography/compound_document.cpp:517\",\n\
                \"#3  0x000000000048a2d9 in xlnt::detail::decrypt_xlsx (data=std::vector of length 3995, capacity 4096 = {...}, password=) at /xlnt/source/detail/cryptography/xlsx_crypto_consumer.cpp:339\",\n\
                \"#4  0x000000000048a7f6 in xlnt::detail::xlsx_consumer::read (this=0x7fffffffd8f0, source=..., password=) at /xlnt/source/detail/cryptography/xlsx_crypto_consumer.cpp:345\",\n\
                \"#5  0x000000000040ddd6 in xlnt::workbook::load (this=0x7fffffffdbc8, stream=...) at /xlnt/source/workbook/workbook.cpp:901\",\n\
                \"#6  0x00000000004142af in xlnt::workbook::load (this=0x7fffffffdbc8, data=std::vector of length 3995, capacity 3995 = {...}) at /xlnt/source/workbook/workbook.cpp:919\"\n\
        ],\n\
        \"CrashLine\": \"/xlnt/source/detail/cryptography/compound_document.cpp:975\"\n\
    }\n";

        let report: CrashReport = serde_json::from_str(data).unwrap();
        assert!(sarif.add_casr_report(&report, "/xlnt").is_ok());
        let rule = sarif.json.as_object().unwrap()["runs"].as_array().unwrap()[0]
            .as_object()
            .unwrap()["tool"]
            .as_object()
            .unwrap()["driver"]
            .as_object()
            .unwrap()["rules"]
            .as_array()
            .unwrap()[0]
            .as_object()
            .unwrap();
        assert_eq!(rule["name"].as_str().unwrap(), "SourceAv");
        assert_eq!(rule["id"].as_str().unwrap(), "F11");

        let location = sarif.json.as_object().unwrap()["runs"].as_array().unwrap()[0]
            .as_object()
            .unwrap()["results"]
            .as_array()
            .unwrap()[0]
            .as_object()
            .unwrap()["locations"]
            .as_array()
            .unwrap()[0]
            .as_object()
            .unwrap()["physicalLocation"]
            .as_object()
            .unwrap();

        let artifact_loc = location["artifactLocation"].as_object().unwrap();

        assert_eq!(
            artifact_loc["uri"].as_str().unwrap(),
            "source/detail/cryptography/compound_document.cpp"
        );
        assert_eq!(
            location["region"].as_object().unwrap()["startLine"]
                .as_u64()
                .unwrap(),
            975
        );
        let location = sarif.json.as_object().unwrap()["runs"].as_array().unwrap()[0]
            .as_object()
            .unwrap()["results"]
            .as_array()
            .unwrap()[0]
            .as_object()
            .unwrap()["stacks"]
            .as_array()
            .unwrap()[0]
            .as_object()
            .unwrap()["frames"]
            .as_array()
            .unwrap()[4]
            .as_object()
            .unwrap()["location"]
            .as_object()
            .unwrap()["physicalLocation"]
            .as_object()
            .unwrap();

        let artifact_loc = location["artifactLocation"].as_object().unwrap();

        assert_eq!(
            artifact_loc["uri"].as_str().unwrap(),
            "source/workbook/workbook.cpp"
        );
        assert_eq!(
            location["region"].as_object().unwrap()["startLine"]
                .as_u64()
                .unwrap(),
            901
        );
    }
}
