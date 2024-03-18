//! C# module implements `ParseStacktrace` and `Exception` traits for C# reports.
use crate::error::*;
use crate::exception::Exception;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::{ParseStacktrace, Stacktrace, StacktraceEntry};
use regex::Regex;

/// Structure provides an interface for processing the stack trace.
pub struct CSharpStacktrace;

impl ParseStacktrace for CSharpStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let re = Regex::new(r"(?m)^Unhandled [Ee]xception(?::\n|\. )(?:.|\n)*?((?:[ \n\t]*(?:at [\S ]+|--- End of inner exception stack trace ---))+)$").unwrap();

        let Some(cap) = re.captures(stream) else {
            return Err(Error::Casr(
                "The stacktrace format is not recognized".to_string(),
            ));
        };

        Ok(cap
            .get(1)
            .unwrap()
            .as_str()
            .split('\n')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "--- End of inner exception stack trace ---")
            .collect::<Vec<String>>())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let re = Regex::new(r"^at (?P<service_info>\([\S ]+?\) )?(?P<function>\S+?)(?: ?(?P<params>\([\S ]*?\)))?(?: <(?P<base>\w+)(?: \+ (?P<offset>\w+))?>| \[(?P<il_offset>\w+)\])?(?: in (?:<(?P<mvid>[[:xdigit:]]+)(?:#[[:xdigit:]]+)?>|(?P<file>[\S ]+)):(?:line )?(?P<line>\w+))?$").unwrap();

        let Some(cap) = re.captures(entry) else {
            return Err(Error::Casr(format!(
                "Couldn't parse stacktrace line: {entry}"
            )));
        };

        let group_as_str = |name| cap.name(name).map(|m| m.as_str());

        let mut stentry = StacktraceEntry::default();

        if let Some(function) = group_as_str("function") {
            let mut function = function.to_string();

            if let Some(params) = group_as_str("params") {
                function.push_str(params)
            }

            if let Some(service_info) = group_as_str("service_info") {
                function.insert_str(0, service_info);
            }

            stentry.function = function;
        }

        let re_hex = Regex::new(r"^0x([[:xdigit:]]+)$").unwrap();
        let parse_hex = |s| {
            re_hex
                .captures(s)
                .and_then(|c| u64::from_str_radix(c.get(1).unwrap().as_str(), 16).ok())
        };

        if let Some(base) = group_as_str("base") {
            let Some(parsed_base) = parse_hex(base) else {
                return Err(Error::Casr(format!("Couldn't parse address: {base}")));
            };

            if let Some(offset) = group_as_str("offset") {
                let Some(address) = parse_hex(offset)
                    .and_then(|parsed_offset| parsed_base.checked_add(parsed_offset))
                else {
                    return Err(Error::Casr(format!(
                        "Couldn't parse address: {base} + {offset}"
                    )));
                };

                stentry.address = address;
            } else {
                stentry.address = parsed_base;
            }
        } else if let Some(il_offset) = group_as_str("il_offset") {
            let Some(parsed_il_offset) = parse_hex(il_offset) else {
                return Err(Error::Casr(format!(
                    "Couldn't parse IL offset: {il_offset}"
                )));
            };

            stentry.address = parsed_il_offset;
        }

        if let Some(file) = group_as_str("file").or_else(|| group_as_str("mvid")) {
            stentry.debug.file = file.to_string();
        }

        if let Some(line) = group_as_str("line") {
            let Ok(parsed_line) = line.parse::<u64>() else {
                return Err(Error::Casr(format!(
                    "Couldn't parse stacktrace line num: {line}"
                )));
            };

            stentry.debug.line = parsed_line;
        }

        Ok(stentry)
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        entries
            .iter()
            .map(|s| Self::parse_stacktrace_entry(s))
            .collect()
    }
}

/// Structure provides an interface for parsing c# exception message.
pub struct CSharpException;

impl Exception for CSharpException {
    fn parse_exception(stream: &str) -> Option<ExecutionClass> {
        let re = Regex::new(r"(?m)^Unhandled [Ee]xception(:\n|\. )((?:.|\n)*?)\n[ \t]*(?:at [\S ]+|--- End of inner exception stack trace ---)$").unwrap();

        let cap = re.captures(stream)?;

        let delimiter = if cap.get(1).unwrap().as_str() == ":\n" {
            " ---> "
        } else {
            "\n ---> "
        };
        let description = cap.get(2).unwrap().as_str();

        let (exception, message) = description
            .rsplit_once(delimiter)
            .map_or(description, |(_, s)| s)
            .split_once(": ")?;

        Some(ExecutionClass {
            short_description: exception.to_string(),
            description: message.to_string(),
            ..ExecutionClass::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stacktrace::{tests::safe_init_ignore_stack_frames, Filter};

    #[test]
    fn test_csharp_parse_exception() {
        let streams = [
            "
Unhandled Exception:
System.ArithmeticException: 123

321

7
 ---> System.ArgumentException: 1111 ---> System.IO.IOException: cccc

   --- End of inner exception stack trace ---",
            "
Unhandled Exception:
System.ArgumentException: 1111
 ---> System.IO.IOException: cccc
   --- End of inner exception stack trace ---",
            "
Unhandled exception. System.ArgumentException: 1111
 ---> System.IO.IOException: cccc


   at Program.<Main>g__f|0_0(Func`2 d, Int32& l, Int32 m) in /home/user/dotnet/2/Program.cs:line 9",
            "
Unhandled exception. System.ArgumentException: 1111 ---> System.IO.IOException: cccc



   at Program.<Main>g__f|0_0(Func`2 d, Int32& l, Int32 m) in /home/user/dotnet/2/Program.cs:line 9",
        ];

        let exceptions = streams.map(|s| {
            let Some(e) = CSharpException::parse_exception(s) else {
                panic!("Couldn't get C# exception from stream: {s}");
            };
            e
        });

        assert_eq!(exceptions[0].short_description, "System.IO.IOException");
        assert_eq!(exceptions[0].description, "cccc\n");
        assert_eq!(exceptions[1].short_description, "System.IO.IOException");
        assert_eq!(exceptions[1].description, "cccc");
        assert_eq!(exceptions[2].short_description, "System.IO.IOException");
        assert_eq!(exceptions[2].description, "cccc\n\n");
        assert_eq!(exceptions[3].short_description, "System.ArgumentException");
        assert_eq!(
            exceptions[3].description,
            "1111 ---> System.IO.IOException: cccc\n\n\n"
        );
    }

    #[test]
    fn test_csharp_stacktrace() {
        let stream = "Unhandled exception. System.ArithmeticException: 123

321

7

 ---> System.ArgumentException: 1111
 ---> System.IO.IOException: cccc
 ---> System.IO.IOException: bbbb
 ---> System.IO.IOException: aaaa
 ---> System.IO.IOException: I/O error occurred.
   --- End of inner exception stack trace ---
   --- End of inner exception stack trace ---
   --- End of inner exception stack trace ---


   at C.qwe()
   at B..ctor() in /home/user/dotnet/2/A.cs:line 37
   at A`1.<>c.<set_Q>b__1_1() in /home/user/dotnet/2/A.cs:line 15

   at A`1.h[Z](Func`1 a)
   --- End of inner exception stack trace ---
   --- End of inner exception stack trace ---
  at A`1[T].<set_Q>g__g|1_0 (System.Int32[] arr) <0x40b745f0 + 0x00122> in /home/user/mono/2/src/2.cs:13
  at System.Threading._ThreadPoolWaitCallback.PerformWaitCallback () [0x00000] in <c79446e93efd45a0b7bc2f9631593aff>:0

  at A`1[T].set_Q (System.Int32 value) <0x40275140 + 0x00082> in <f6b2b0ea894844dc83a96f9504d8f570#610bc057486c618efb3936233b088988>:0
  at (wrapper runtime-invoke) staticperformanceoptimization.runtime_invoke_void (object,intptr,intptr,intptr) <0xffffffff>


  at (wrapper managed-to-native) System.Drawing.GDIPlus:GdiplusStartup (ulong&,System.Drawing.GdiplusStartupInput&,System.Drawing.GdiplusStartupOutput&)
  at Program+<>c.<Main>b__0_2 (System.Int32 i) <0x7f1c08e516b0 + 0x00035> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0
  at Program.<Main>g__f|0_0 (System.Func`2[T,TResult] d, System.Int32& l, System.Int32 m) <0x7f1c08e51140 + 0x000d9> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0
  at Program.Main () <0x7f1c08e51010 + 0x000ea> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0
";

        let trace = [
            "at C.qwe()",
            "at B..ctor() in /home/user/dotnet/2/A.cs:line 37",
            "at A`1.<>c.<set_Q>b__1_1() in /home/user/dotnet/2/A.cs:line 15",
            "at A`1.h[Z](Func`1 a)",
            "at A`1[T].<set_Q>g__g|1_0 (System.Int32[] arr) <0x40b745f0 + 0x00122> in /home/user/mono/2/src/2.cs:13",
            "at System.Threading._ThreadPoolWaitCallback.PerformWaitCallback () [0x00000] in <c79446e93efd45a0b7bc2f9631593aff>:0",
            "at A`1[T].set_Q (System.Int32 value) <0x40275140 + 0x00082> in <f6b2b0ea894844dc83a96f9504d8f570#610bc057486c618efb3936233b088988>:0",
            "at (wrapper runtime-invoke) staticperformanceoptimization.runtime_invoke_void (object,intptr,intptr,intptr) <0xffffffff>",
            "at (wrapper managed-to-native) System.Drawing.GDIPlus:GdiplusStartup (ulong&,System.Drawing.GdiplusStartupInput&,System.Drawing.GdiplusStartupOutput&)",
            "at Program+<>c.<Main>b__0_2 (System.Int32 i) <0x7f1c08e516b0 + 0x00035> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0",
            "at Program.<Main>g__f|0_0 (System.Func`2[T,TResult] d, System.Int32& l, System.Int32 m) <0x7f1c08e51140 + 0x000d9> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0",
            "at Program.Main () <0x7f1c08e51010 + 0x000ea> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0"
        ].map(String::from).to_vec();

        let bt = CSharpStacktrace::extract_stacktrace(stream).unwrap();

        assert_eq!(bt, trace);

        let mut stacktrace = match CSharpStacktrace::parse_stacktrace(&trace) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };

        assert_eq!(stacktrace.len(), 12);

        assert_eq!(stacktrace[0].function, "C.qwe()".to_string());
        assert_eq!(stacktrace[1].function, "B..ctor()".to_string());
        assert_eq!(
            stacktrace[1].debug.file,
            "/home/user/dotnet/2/A.cs".to_string()
        );
        assert_eq!(stacktrace[1].debug.line, 37);
        assert_eq!(
            stacktrace[2].function,
            "A`1.<>c.<set_Q>b__1_1()".to_string()
        );
        assert_eq!(
            stacktrace[2].debug.file,
            "/home/user/dotnet/2/A.cs".to_string()
        );
        assert_eq!(stacktrace[2].debug.line, 15);
        assert_eq!(stacktrace[6].address, 1076318658);
        assert_eq!(
            stacktrace[6].function,
            "A`1[T].set_Q(System.Int32 value)".to_string()
        );
        assert_eq!(
            stacktrace[6].debug.file,
            "f6b2b0ea894844dc83a96f9504d8f570".to_string()
        );
        assert_eq!(stacktrace[6].debug.line, 0);
        assert_eq!(stacktrace[7].address, 0xffffffff);
        assert_eq!(
            stacktrace[7].function,
            "(wrapper runtime-invoke) staticperformanceoptimization.runtime_invoke_void(object,intptr,intptr,intptr)".to_string()
        );
        assert_eq!(
            stacktrace[8].function,
            "(wrapper managed-to-native) System.Drawing.GDIPlus:GdiplusStartup(ulong&,System.Drawing.GdiplusStartupInput&,System.Drawing.GdiplusStartupOutput&)".to_string()
        );
        assert_eq!(stacktrace[9].address, 139758385043173);
        assert_eq!(
            stacktrace[9].function,
            "Program+<>c.<Main>b__0_2(System.Int32 i)".to_string()
        );
        assert_eq!(
            stacktrace[9].debug.file,
            "f6b2b0ea894844dc83a96f9504d8f570".to_string()
        );
        assert_eq!(stacktrace[9].debug.line, 0);
        assert_eq!(
            stacktrace[10].function,
            "Program.<Main>g__f|0_0(System.Func`2[T,TResult] d, System.Int32& l, System.Int32 m)"
                .to_string()
        );
        assert_eq!(stacktrace[10].address, 139758385041945);
        assert_eq!(
            stacktrace[10].debug.file,
            "f6b2b0ea894844dc83a96f9504d8f570".to_string()
        );
        assert_eq!(stacktrace[10].debug.line, 0);

        safe_init_ignore_stack_frames();
        stacktrace.filter();

        assert_eq!(stacktrace.len(), 4);

        assert_eq!(stacktrace[0].function, "A`1.h[Z](Func`1 a)".to_string());
        assert_eq!(stacktrace[1].address, 1085753106);
        assert_eq!(
            stacktrace[1].function,
            "A`1[T].<set_Q>g__g|1_0(System.Int32[] arr)".to_string()
        );
        assert_eq!(
            stacktrace[1].debug.file,
            "/home/user/mono/2/src/2.cs".to_string()
        );
        assert_eq!(stacktrace[1].debug.line, 13);
        assert_eq!(stacktrace[2].address, 0);
        assert_eq!(
            stacktrace[2].function,
            "System.Threading._ThreadPoolWaitCallback.PerformWaitCallback()".to_string()
        );
        assert_eq!(
            stacktrace[2].debug.file,
            "c79446e93efd45a0b7bc2f9631593aff".to_string()
        );
        assert_eq!(stacktrace[2].debug.line, 0);
        assert_eq!(stacktrace[3].address, 139758385041658);
        assert_eq!(stacktrace[3].function, "Program.Main()".to_string());
        assert_eq!(
            stacktrace[3].debug.file,
            "f6b2b0ea894844dc83a96f9504d8f570".to_string()
        );
        assert_eq!(stacktrace[3].debug.line, 0);
    }
}
