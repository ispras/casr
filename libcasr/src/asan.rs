//! Asan module implements `ParseStacktrace`, `Exception` and `Severity` traits for AddressSanitizer
//! reports.
use regex::Regex;

use crate::error::*;
use crate::execution_class::{is_near_null, ExecutionClass};
use crate::severity::Severity;
use crate::stacktrace::ParseStacktrace;
use crate::stacktrace::*;

/// Structure provides an interface for processing the stack trace.
pub struct AsanStacktrace;

impl ParseStacktrace for AsanStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let lines: Vec<String> = stream.split('\n').map(|l| l.to_string()).collect();

        let Some(first) = lines.iter().position(|x| x.contains(" #0 ")) else {
            return Err(Error::Casr(
                "Couldn't find stack trace in sanitizer's report".to_string(),
            ));
        };

        // Stack trace is split by empty line.
        let Some(last) = lines.iter().skip(first).position(|val| val.is_empty()) else {
            return Err(Error::Casr(
                "Couldn't find stack trace end in sanitizer's report".to_string(),
            ));
        };
        Ok(lines[first..first + last].to_vec())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let mut stentry = StacktraceEntry::default();

        // #10 0xdeadbeef
        let re = Regex::new(r"^ *#[0-9]+ +0x([0-9a-f]+) *").unwrap();
        let Some(caps) = re.captures(entry.as_ref()) else {
            return Err(Error::Casr(format!(
                "Couldn't parse frame and address in stack trace entry: {entry}"
            )));
        };

        // Get address.
        let num = caps.get(1).unwrap().as_str();
        let addr = u64::from_str_radix(num, 16);
        if addr.is_err() {
            return Err(Error::Casr(format!("Couldn't parse address: {num}")));
        }
        stentry.address = addr.unwrap();

        // Cut frame and address from string.
        let mut location = entry[caps.get(0).unwrap().as_str().len()..].trim();

        // Determine whether entry has function name.
        // TODO: there may be no function and source path may start with in and space.
        let has_function = location.starts_with("in ");

        // (module+0xdeadbeef)
        // TODO: (module)
        // We have to distinguish from (anonymous namespace) and function arguments.
        // TODO: module path may contain (.
        // We forbid ( in module path to distinguish from function arguments.
        // However, we allow ( when there is no function.
        // Regex::captures returns leftmost-first match, so, it won't match (BuildId: ).
        let re = if has_function {
            Regex::new(r"\(([^(]+)\+0x([0-9a-f]+)\)").unwrap()
        } else {
            Regex::new(r"\((.+)\+0x([0-9a-f]+)\)").unwrap()
        };
        if let Some(caps) = re.captures(location.as_ref()) {
            // Get module name.
            stentry.module = caps.get(1).unwrap().as_str().trim().to_string();
            // Get offset in module.
            let num = caps.get(2).unwrap().as_str();
            let off = u64::from_str_radix(num, 16);
            if off.is_err() {
                return Err(Error::Casr(format!("Couldn't parse module offset: {num}")));
            }
            stentry.offset = off.unwrap();
            // Cut module from string.
            location = location[..caps.get(0).unwrap().start()].trim();
        }

        // in function[(args)] [const] path
        // TODO: source file path may contain )
        if has_function {
            if location.len() < 3 {
                return Err(Error::Casr(format!(
                    "Couldn't parse stack trace entry: {entry}"
                )));
            }
            location = location[3..].trim();
            // in typeinfo name for xlnt::detail::compound_document_istreambuf
            // TODO: there may be no function and source path may start with for and space.
            if let Some(f) = location.find(" for ") {
                location = location[f + 5..].trim();
            }
            if location.is_empty() {
                return Err(Error::Casr(format!(
                    "Couldn't parse function name: {entry}"
                )));
            }
            if location.ends_with(") const") {
                // There is no source file path.
                stentry.function = location.to_string();
                return Ok(stentry);
            }
            let i = if let Some(p) = location.rfind(')') {
                if location[p..].starts_with(") const ") {
                    p + 7
                } else {
                    p
                }
            } else {
                location.find(' ').unwrap_or(0)
            };
            let space_after_paren = location[i..].find(' ');
            if space_after_paren.is_none() {
                // Get function name.
                stentry.function = location.to_string();
                // No source path.
                return Ok(stentry);
            }
            let space_after_paren = space_after_paren.unwrap() + i;
            // Get function name.
            stentry.function = location[..space_after_paren].to_string();
            // Cut function name from string.
            location = location[space_after_paren..].trim();
        }

        // file[:line[:column]]
        // TODO: path may contain :
        if !location.is_empty() {
            let source: Vec<&str> = location.rsplitn(3, ':').collect();
            if source.iter().any(|x| x.is_empty()) {
                return Err(Error::Casr(format!(
                    "Couldn't parse source file path, line, or column: {location}"
                )));
            }
            // Get source file.
            stentry.debug.file = source.last().unwrap().trim().to_string();
            // Get source line (optional).
            if source.len() > 1 {
                let num = source[source.len() - 2];
                let line = num.parse::<u64>();
                if line.is_err() {
                    return Err(Error::Casr(format!("Couldn't parse source line: {num}")));
                }
                stentry.debug.line = line.unwrap();
            }
            // Get source column (optional).
            if source.len() == 3 {
                let num = source[0];
                let column = num.parse::<u64>();
                if column.is_err() {
                    return Err(Error::Casr(format!("Couldn't parse source column: {num}")));
                }
                stentry.debug.column = column.unwrap();
            }
        }

        Ok(stentry)
    }
}

/// Information about sanitizer crash state.
pub struct AsanContext(pub Vec<String>);

impl Severity for AsanContext {
    fn severity(&self) -> Result<ExecutionClass> {
        let asan_report = &self.0;
        if asan_report.is_empty() {
            return Err(Error::Casr(
                "Cannot estimate severity: Asan is empty.".to_string(),
            ));
        }
        if asan_report[0].contains("LeakSanitizer") {
            ExecutionClass::find("memory-leaks")
        } else {
            let summary =
                Regex::new(r"SUMMARY: *(AddressSanitizer|libFuzzer): ([A-Za-z_\-\(\)]+)").unwrap();

            let Some(caps) = asan_report.iter().find_map(|s| summary.captures(s)) else {
                return Err(Error::Casr(
                    "Cannot find SUMMARY in Sanitizer report".to_string(),
                ));
            };
            // Match Sanitizer.
            match caps.get(1).unwrap().as_str() {
                "libFuzzer" => ExecutionClass::san_find(caps.get(2).unwrap().as_str(), None, false),
                _ => {
                    // AddressSanitizer
                    let san_type = caps.get(2).unwrap().as_str();
                    let mem_access = if let Some(second_line) = asan_report.get(1) {
                        let raccess = Regex::new(r"(READ|WRITE|ACCESS)").unwrap();
                        if let Some(access_type) = raccess.captures(second_line) {
                            Some(access_type.get(1).unwrap().as_str())
                        } else if let Some(third_line) = asan_report.get(2) {
                            raccess
                                .captures(third_line)
                                .map(|access_type| access_type.get(1).unwrap().as_str())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let rcrash_address = Regex::new("on.*address 0x([0-9a-f]+)").unwrap();
                    let near_null =
                        if let Some(crash_address) = rcrash_address.captures(&asan_report[0]) {
                            let Ok(addr) =
                                u64::from_str_radix(crash_address.get(1).unwrap().as_str(), 16)
                            else {
                                return Err(Error::Casr(format!(
                                    "Cannot parse address: {}",
                                    crash_address.get(1).unwrap().as_str()
                                )));
                            };
                            is_near_null(addr)
                        } else {
                            false
                        };
                    ExecutionClass::san_find(san_type, mem_access, near_null)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asan_stacktrace() {
        let raw_stacktrace = &[ "#10 0x55ebfbfa0707 (/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz+0xfe2707) (BuildId: d2918819a864502448a61485c4b20818b0778ac2)",
            "#6 0x55ebfc1cabbc in rz_bin_open_buf (/home/user/Desk top/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz+0x120cbbc)",
            "#10 0x55ebfbfa0707 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz+0xfe2707)",
            "#9 0x43b1a1 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15",
            "#7 0x52433e in cmsIT8LoadFromMem /lcms/src/cmscgats.c:2438:10",
            "#7 0x52433e in cmsIT8LoadFromMem /lcms/src/cmscgats.c:2438",
            "#7 0x52433e in cmsIT8LoadFromMem /lcms/src/cmscgats.c",
            "#9 0x43b1a1 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp",
            "#4 0x998b40 in (anonymous namespace)::decrypt_xlsx(std::vector<unsigned char, std::allocator<unsigned char> > const&, std::__cxx11::basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t> > const&) /xlnt/source/detail/cryptography/xlsx_crypto_consumer.cpp:320:37",
            "#0 0x7f0a52c0fc59  /build/glibc-SzIz7B/glibc-2.31/string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:345",
            "#2 0x55ebfc21e12d in classes bin_dyldcache.c",
            "#2 0x55ebfc21e12d in classes+0x123 bin_dyldcache.c",
            "#2 0x55ebfc21e12d in classes+0x123 bin dyldcache.c",
            "#2 0x55ebfc21e12d bin_dyldcache.c",
            "#2 0x55ebfc21e12d bin dyldcache.c",
            "#9 0x43b1a1 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm -project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp",
            "#10 0x55ebfbfa0707 (/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz+0xfe2707) (BuildId: d2918819a864502448a61485c4b20818b0778ac2)",
            "#11 0xe086ff in xml::serializer::handle_error(genxStatus) const /xlnt/third-party/libstudxml/libstudxml/serializer.cxx:116:7",
            "    #7 0xa180bf in typeinfo name for xlnt::detail::compound_document_istreambuf (/load_afl+0xa180bf)",
            "    #9 0xb98663 in xlnt::detail::number_serialiser::deserialise(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, long*) const (/casr_tests/bin/load_fuzzer+0xb98663)",
        ];

        let trace = raw_stacktrace
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>();
        let sttr = AsanStacktrace::parse_stacktrace(&trace);
        if sttr.is_err() {
            panic!("{}", sttr.err().unwrap());
        }

        let stacktrace = sttr.unwrap();
        assert_eq!(stacktrace[0].address, 0x55ebfbfa0707);
        assert_eq!(stacktrace[0].offset, 0xfe2707);
        assert_eq!(
            stacktrace[0].module,
            "/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz"
                .to_string()
        );

        assert_eq!(stacktrace[1].address, 0x55ebfc1cabbc);
        assert_eq!(stacktrace[1].offset, 0x120cbbc);
        assert_eq!(
            stacktrace[1].module,
            "/home/user/Desk top/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz"
                .to_string()
        );
        assert_eq!(stacktrace[1].function, "rz_bin_open_buf".to_string());

        assert_eq!(stacktrace[2].address, 0x55ebfbfa0707);
        assert_eq!(stacktrace[2].offset, 0xfe2707);
        assert_eq!(
            stacktrace[2].module,
            "/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz"
                .to_string()
        );
        assert_eq!(
            stacktrace[2].function,
            "fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long))"
                .to_string()
        );

        assert_eq!(stacktrace[3].address, 0x43b1a1);
        assert_eq!(
            stacktrace[3].function,
            "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)".to_string()
        );
        assert_eq!(
            stacktrace[3].debug.file,
            "/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp".to_string()
        );
        assert_eq!(stacktrace[3].debug.line, 611);
        assert_eq!(stacktrace[3].debug.column, 15);

        assert_eq!(stacktrace[4].address, 0x52433e);
        assert_eq!(stacktrace[4].function, "cmsIT8LoadFromMem".to_string());
        assert_eq!(stacktrace[4].debug.file, "/lcms/src/cmscgats.c".to_string());
        assert_eq!(stacktrace[4].debug.line, 2438);
        assert_eq!(stacktrace[4].debug.column, 10);

        assert_eq!(stacktrace[5].address, 0x52433e);
        assert_eq!(stacktrace[5].function, "cmsIT8LoadFromMem".to_string());
        assert_eq!(stacktrace[5].debug.file, "/lcms/src/cmscgats.c".to_string());
        assert_eq!(stacktrace[5].debug.line, 2438);

        assert_eq!(stacktrace[6].address, 0x52433e);
        assert_eq!(stacktrace[6].function, "cmsIT8LoadFromMem".to_string());
        assert_eq!(stacktrace[6].debug.file, "/lcms/src/cmscgats.c".to_string());

        assert_eq!(stacktrace[7].address, 0x43b1a1);
        assert_eq!(
            stacktrace[7].function,
            "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)".to_string()
        );
        assert_eq!(
            stacktrace[7].debug.file,
            "/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp".to_string()
        );

        assert_eq!(stacktrace[8].address, 0x998b40);
        assert_eq!(stacktrace[8].function, "(anonymous namespace)::decrypt_xlsx(std::vector<unsigned char, std::allocator<unsigned char> > const&, std::__cxx11::basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t> > const&)".to_string());
        assert_eq!(
            stacktrace[8].debug.file,
            "/xlnt/source/detail/cryptography/xlsx_crypto_consumer.cpp".to_string()
        );
        assert_eq!(stacktrace[8].debug.line, 320);
        assert_eq!(stacktrace[8].debug.column, 37);

        assert_eq!(stacktrace[9].address, 0x7f0a52c0fc59);
        assert_eq!(
            stacktrace[9].debug.file,
            "/build/glibc-SzIz7B/glibc-2.31/string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S".to_string()
        );
        assert_eq!(stacktrace[9].debug.line, 345);

        assert_eq!(stacktrace[10].address, 0x55ebfc21e12d);
        assert_eq!(stacktrace[10].function, "classes");
        assert_eq!(stacktrace[10].debug.file, "bin_dyldcache.c");

        assert_eq!(stacktrace[11].address, 0x55ebfc21e12d);
        assert_eq!(stacktrace[11].function, "classes+0x123");
        assert_eq!(stacktrace[11].debug.file, "bin_dyldcache.c");

        assert_eq!(stacktrace[12].address, 0x55ebfc21e12d);
        assert_eq!(stacktrace[12].function, "classes+0x123");
        assert_eq!(stacktrace[12].debug.file, "bin dyldcache.c");

        assert_eq!(stacktrace[13].address, 0x55ebfc21e12d);
        assert_eq!(stacktrace[13].debug.file, "bin_dyldcache.c");

        assert_eq!(stacktrace[14].address, 0x55ebfc21e12d);
        assert_eq!(stacktrace[14].debug.file, "bin dyldcache.c");

        assert_eq!(stacktrace[15].address, 0x43b1a1);
        assert_eq!(
            stacktrace[15].function,
            "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)".to_string()
        );
        assert_eq!(
            stacktrace[15].debug.file,
            "/llvm -project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp".to_string()
        );

        assert_eq!(stacktrace[16].address, 0x55ebfbfa0707);
        assert_eq!(stacktrace[16].offset, 0xfe2707);
        assert_eq!(
            stacktrace[16].module,
            "/home/user/Desktop/fuzz-targets/rz-installation-libfuzzer-asan/bin/rz-fuzz"
                .to_string()
        );

        assert_eq!(stacktrace[17].address, 0xe086ff);
        assert_eq!(
            stacktrace[17].function,
            "xml::serializer::handle_error(genxStatus) const".to_string()
        );
        assert_eq!(
            stacktrace[17].debug.file,
            "/xlnt/third-party/libstudxml/libstudxml/serializer.cxx".to_string()
        );
        assert_eq!(stacktrace[17].debug.line, 116);
        assert_eq!(stacktrace[17].debug.column, 7);

        assert_eq!(stacktrace[18].address, 0xa180bf);
        assert_eq!(
            stacktrace[18].function,
            "xlnt::detail::compound_document_istreambuf".to_string()
        );
        assert_eq!(stacktrace[18].module, "/load_afl".to_string());
        assert_eq!(stacktrace[18].offset, 0xa180bf);

        assert_eq!(stacktrace[19].address, 0xb98663);
        assert_eq!(
            stacktrace[19].function,
            "xlnt::detail::number_serialiser::deserialise(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, long*) const".to_string()
        );
        assert_eq!(
            stacktrace[19].module,
            "/casr_tests/bin/load_fuzzer".to_string()
        );
        assert_eq!(stacktrace[19].offset, 0xb98663);
    }
}
