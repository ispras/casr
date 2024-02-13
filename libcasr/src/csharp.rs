//! C# module implements `ParseStacktrace` and `Exception` traits for C# reports.
use crate::exception::Exception;
use crate::stacktrace::{ParseStacktrace, Stacktrace};

use crate::error::*;
use crate::execution_class::ExecutionClass;
use crate::stacktrace::StacktraceEntry;

use regex::Regex;

/// Structure provides an interface for processing the stack trace.
pub struct CSharpStacktrace;

impl CSharpStacktrace {
    fn get_regex_format_for_stacktrace_entry(entry: &str) -> Result<Regex> {
        let regexps = [
            // DotNet
            Regex::new(r"^at (?:(?P<service_info>\(.+?\)) )?(?P<function>\S+?)(?P<params>\(.*?\))?(?: in (?P<file>.+):line (?P<line>\w+))?$").unwrap(),
            // Mono
            Regex::new(r"^at (?:(?P<service_info>\(.+?\)) )?(?P<function>\S+?)(?: ?(?P<params>\(.*?\)))?(?: (?:<(?P<base>\w+)(?: \+ (?P<offset>\w+))?>|\[0x[\da-fA-F]+\]))?(?: in (?:<[\da-fA-F#]+>|(?P<file>.+)):(?P<line>\w+))?$").unwrap()
        ];

        for re in regexps {
            if re.is_match(entry) {
                return Ok(re);
            }
        }

        Err(Error::Casr(format!("Couldn't parse stacktrace line: {entry}")))
    }

    fn parse_stacktrace_entry(entry: &str, format_regex: &Regex) -> Result<StacktraceEntry> {
        let Some(cap) = format_regex.captures(entry) else {
            return Err(Error::Casr(format!("Couldn't parse stacktrace line: {entry}")));
        };

        let get_group_by_name_as_str = |name| cap.name(name).map(|m| m.as_str());

        let mut stentry = StacktraceEntry::default();

        if let Some(file) = get_group_by_name_as_str("file") {
            stentry.debug.file = file.to_string();
        }

        if let Some(line) = get_group_by_name_as_str("line") {
            let Ok(parsed_line) = line.parse::<u64>() else {
                return Err(Error::Casr(format!("Couldn't parse stacktrace line num: {line}")))
            };

            stentry.debug.line = parsed_line;
        }

        if let (Some(base), Some(offset)) = (get_group_by_name_as_str("base"), get_group_by_name_as_str("offset")) {
            let re_hex = Regex::new(r"^0x([\da-fA-F]+)$").unwrap();
            let parse_hex = |s| re_hex
                .captures(s)
                .and_then(|c| u64::from_str_radix(c.get(1).unwrap().as_str(), 16).ok());

            if let (Some(parsed_base), Some(parsed_offset)) = (parse_hex(base), parse_hex(offset)) {
                if let Some(address) = parsed_base.checked_add(parsed_offset) {
                    stentry.address = address;
                } else {
                    return Err(Error::Casr(format!("Couldn't parse address: {base} + {offset}")));
                }
            } else {
                return Err(Error::Casr(format!("Couldn't parse address: {base} + {offset}")));
            };
        };

        if let Some(function) = get_group_by_name_as_str("function") {
            let mut function = function.to_string();

            if let Some(params) = get_group_by_name_as_str("params") {
                function.push_str(params)
            }

            if let Some(service_info) = get_group_by_name_as_str("service_info") {
                function = format!("{service_info} {function}");
            }

            stentry.function = function;
        }

        Ok(stentry)
    }
}

impl ParseStacktrace for CSharpStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let re = Regex::new(r"(?m)^Unhandled (e|E)xception(\. |:\n)(?:.|\n)*?((?:\s*(?:at [\S ]+|--- End of inner exception stack trace ---))+)$").unwrap();

        let Some(cap) = re.captures(stream).and_then(|cap|
            ((cap.get(1).unwrap().as_str() == "E") == (cap.get(2).unwrap().as_str() == ":\n")).then_some(cap)
        ) else {
            return Err(Error::Casr("The stacktrace format is not recognized".to_string()));
        };

        Ok(cap
            .get(3)
            .unwrap()
            .as_str()
            .split('\n')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        Self::parse_stacktrace_entry(entry, &Self::get_regex_format_for_stacktrace_entry(entry)?)
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        let mut iter = entries
            .iter()
            .scan((true, false), |(first_block, skip), s| {
                // Skipping all blocks consisting of "--- End of inner exception stack trace ---"
                // and one stack frame after each such block, except for the first block if entries start with it.
                let not_stack_trace_entry = s == "--- End of inner exception stack trace ---";

                if not_stack_trace_entry || *skip {
                    *skip = not_stack_trace_entry;

                    if !*first_block || not_stack_trace_entry {
                        return Some("");
                    }
                }

                *first_block = false;

                Some(s)
            })
            .filter(|&s| !s.is_empty()).peekable();

        if let Some(s) = iter.peek() {
            let re = Self::get_regex_format_for_stacktrace_entry(s)?;
            return iter.map(|s| Self::parse_stacktrace_entry(s, &re)).collect();
        }

        return std::iter::empty::<Result<StacktraceEntry>>().collect();
    }
}

/// Structure provides an interface for parsing c# exception message.
pub struct CSharpException;

impl Exception for CSharpException {
    fn parse_exception(stream: &str) -> Option<ExecutionClass> {
        let re = Regex::new(r"(?m)^Unhandled (e|E)xception(\. |:\n)((?:.|\n)*?)\s*(?:at [\S ]+|--- End of inner exception stack trace ---)$").unwrap();

        let cap = re.captures(stream)?;
        let get_group_as_str = |i| cap.get(i).unwrap().as_str();

        let is_mono = get_group_as_str(1) == "E";

        if is_mono != (get_group_as_str(2) == ":\n") { return None; }

        let description = get_group_as_str(3);
        let delimiter = if is_mono { " ---> " } else { "\n ---> " };

        let (exception, message) = description
            .rsplit_once(delimiter)
            .map_or(description, |(_, s)| s)
            .split_once(": ")?;

        Some(ExecutionClass { short_description: exception.to_string(), description: message.to_string(), ..ExecutionClass::default()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{init_ignored_frames, stacktrace::Filter};

    #[test]
    fn test_csharp_get_regex_format_for_stacktrace_entry() {
        let re_dotnet = r"^at (?:(?P<service_info>\(.+?\)) )?(?P<function>\S+?)(?P<params>\(.*?\))?(?: in (?P<file>.+):line (?P<line>\w+))?$";
        let re_mono = r"^at (?:(?P<service_info>\(.+?\)) )?(?P<function>\S+?)(?: ?(?P<params>\(.*?\)))?(?: (?:<(?P<base>\w+)(?: \+ (?P<offset>\w+))?>|\[0x[\da-fA-F]+\]))?(?: in (?:<[\da-fA-F#]+>|(?P<file>.+)):(?P<line>\w+))?$";

        fn get_regex(entry: &str) -> Result<String> {
            CSharpStacktrace::get_regex_format_for_stacktrace_entry(entry).map(|r| r.to_string())
        }

        match get_regex("at A`1[T].h[Z] (System.Func`1[TResult] a) [0x00001] in <f6b2b0ea894844dc83a96f9504d8f570>:0") {
            Ok(re) => assert_eq!(re, re_mono),
            Err(err) => panic!("{err}")
        }

        match get_regex("at A`1.<set_Q>g__g|1_0(Int32[] arr(((((((((( in /home/user/dotnet/2/A.cs:line 19") {
            Ok(_) => assert!(false),
            Err(err) => assert_eq!(err.to_string(), "Casr: Couldn't parse stacktrace line: at A`1.<set_Q>g__g|1_0(Int32[] arr(((((((((( in /home/user/dotnet/2/A.cs:line 19")
        }

        match get_regex("at Program+<>c.<Main>b__0_2 (System.Int32 i) <0x7f30488306b0 + 0x00035> in <f6b2b0ea894844dc83a96f9504d8f570#610bc057486c618efb3936233b088988>:0") {
            Ok(re) => assert_eq!(re, re_mono),
            Err(err) => panic!("{err}")
        }

        match get_regex("at (wrapper managed-to-native) System.Drawing.GDIPlus:GdiplusStartup (ulong&,System.Drawing.GdiplusStartupInput&,System.Drawing.GdiplusStartupOutput&)") {
            Ok(re) => assert_eq!(re, re_mono),
            Err(err) => panic!("{err}")
        }

        match get_regex("at Program.<Main>g__f|0_0(Func`2 d, Int32& l, Int32 m) in /home/user/dotnet/2/Program.cs:line 9") {
            Ok(re) => assert_eq!(re, re_dotnet),
            Err(err) => panic!("{err}")
        }

        match get_regex("at Program.Main()") {
            Ok(re) => assert_eq!(re, re_dotnet),
            Err(err) => panic!("{err}")
        }
    }

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
   --- End of inner exception stack trace ---",
            "
Unhandled exception. System.ArgumentException: 1111 ---> System.IO.IOException: cccc
   --- End of inner exception stack trace ---"
        ];

        let exceptions = streams.map(|s| {
            let Some(e) = CSharpException::parse_exception(s) else {
                panic!("Couldn't get C# exception from stream: {s}");
            };
            e
        });

        assert_eq!(exceptions[0].short_description, "System.IO.IOException");
        assert_eq!(exceptions[0].description, "cccc");
        assert_eq!(exceptions[1].short_description, "System.IO.IOException");
        assert_eq!(exceptions[1].description, "cccc");
        assert_eq!(exceptions[2].short_description, "System.IO.IOException");
        assert_eq!(exceptions[2].description, "cccc");
        assert_eq!(exceptions[3].short_description, "System.ArgumentException");
        assert_eq!(exceptions[3].description, "1111 ---> System.IO.IOException: cccc");
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
   at B..ctor() in /home/user/dotnet/2/A.cs:line 37
   at A`1.<>c.<set_Q>b__1_1() in /home/user/dotnet/2/A.cs:line 15
   at A`1.h[Z](Func`1 a)
   --- End of inner exception stack trace ---
   --- End of inner exception stack trace ---
  at A`1.h[Z](Func`1 a)
  at A`1[T].<set_Q>g__g|1_0 (System.Int32[] arr) <0x40b745f0 + 0x00122> in /home/user/mono/2/src/2.cs:13
  at A`1[T].set_Q (System.Int32 value) <0x40275140 + 0x00082> in <f6b2b0ea894844dc83a96f9504d8f570#610bc057486c618efb3936233b088988>:0
  at (wrapper runtime-invoke) staticperformanceoptimization.runtime_invoke_void (object,intptr,intptr,intptr) <0xffffffff>
  at (wrapper managed-to-native) System.Drawing.GDIPlus:GdiplusStartup (ulong&,System.Drawing.GdiplusStartupInput&,System.Drawing.GdiplusStartupOutput&)
  at Program+<>c.<Main>b__0_2 (System.Int32 i) <0x7f1c08e516b0 + 0x00035> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0
  at Program.<Main>g__f|0_0 (System.Func`2[T,TResult] d, System.Int32& l, System.Int32 m) <0x7f1c08e51140 + 0x000d9> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0
  at Program.Main () <0x7f1c08e51010 + 0x000ea> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0
";

        let trace = [
            "--- End of inner exception stack trace ---",
            "--- End of inner exception stack trace ---",
            "--- End of inner exception stack trace ---",
            "at B..ctor() in /home/user/dotnet/2/A.cs:line 37",
            "at A`1.<>c.<set_Q>b__1_1() in /home/user/dotnet/2/A.cs:line 15",
            "at A`1.h[Z](Func`1 a)",
            "--- End of inner exception stack trace ---",
            "--- End of inner exception stack trace ---",
            "at A`1.h[Z](Func`1 a)",
            "at A`1[T].<set_Q>g__g|1_0 (System.Int32[] arr) <0x40b745f0 + 0x00122> in /home/user/mono/2/src/2.cs:13",
            "at A`1[T].set_Q (System.Int32 value) <0x40275140 + 0x00082> in <f6b2b0ea894844dc83a96f9504d8f570#610bc057486c618efb3936233b088988>:0",
            "at (wrapper runtime-invoke) staticperformanceoptimization.runtime_invoke_void (object,intptr,intptr,intptr) <0xffffffff>",
            "at (wrapper managed-to-native) System.Drawing.GDIPlus:GdiplusStartup (ulong&,System.Drawing.GdiplusStartupInput&,System.Drawing.GdiplusStartupOutput&)",
            "at Program+<>c.<Main>b__0_2 (System.Int32 i) <0x7f1c08e516b0 + 0x00035> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0",
            "at Program.<Main>g__f|0_0 (System.Func`2[T,TResult] d, System.Int32& l, System.Int32 m) <0x7f1c08e51140 + 0x000d9> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0",
            "at Program.Main () <0x7f1c08e51010 + 0x000ea> in <f6b2b0ea894844dc83a96f9504d8f570#17898f75ae7b737216569c39168a3967>:0"
        ].map(String::from).to_vec();

        let bt = CSharpStacktrace::extract_stacktrace(stream).unwrap();

        assert_eq!(bt, trace);

        let mut stacktrace = match CSharpStacktrace::parse_stacktrace(&trace[0..8]) {
            Ok(s) => s,
            Err(e) => panic!("{e}")
        };

        assert_eq!(stacktrace.len(), 3);
        assert_eq!(stacktrace[0].function, "B..ctor()".to_string());
        assert_eq!(stacktrace[0].debug.file, "/home/user/dotnet/2/A.cs".to_string());
        assert_eq!(stacktrace[0].debug.line, 37);
        assert_eq!(stacktrace[1].function, "A`1.<>c.<set_Q>b__1_1()".to_string());
        assert_eq!(stacktrace[1].debug.file, "/home/user/dotnet/2/A.cs".to_string());
        assert_eq!(stacktrace[1].debug.line, 15);
        assert_eq!(stacktrace[2].function, "A`1.h[Z](Func`1 a)".to_string());

        stacktrace = match CSharpStacktrace::parse_stacktrace(&trace[9..16]) {
            Ok(s) => s,
            Err(e) => panic!("{e}")
        };

        assert_eq!(stacktrace.len(), 7);
        assert_eq!(
            stacktrace[2].function,
            "(wrapper runtime-invoke) staticperformanceoptimization.runtime_invoke_void(object,intptr,intptr,intptr)".to_string()
        );
        assert_eq!(
            stacktrace[3].function,
            "(wrapper managed-to-native) System.Drawing.GDIPlus:GdiplusStartup(ulong&,System.Drawing.GdiplusStartupInput&,System.Drawing.GdiplusStartupOutput&)".to_string()
        );

        init_ignored_frames!("csharp");
        stacktrace.filter();

        assert_eq!(stacktrace.len(), 5);
        assert_eq!(stacktrace[0].address, 1085753106);
        assert_eq!(stacktrace[0].function, "A`1[T].<set_Q>g__g|1_0(System.Int32[] arr)".to_string());
        assert_eq!(stacktrace[0].debug.file, "/home/user/mono/2/src/2.cs".to_string());
        assert_eq!(stacktrace[0].debug.line, 13);
        assert_eq!(stacktrace[1].address, 1076318658);
        assert_eq!(stacktrace[1].function, "A`1[T].set_Q(System.Int32 value)".to_string());

        assert_eq!(stacktrace[2].address, 139758385043173);
        assert_eq!(stacktrace[2].function, "Program+<>c.<Main>b__0_2(System.Int32 i)".to_string());
        assert_eq!(stacktrace[3].address, 139758385041945);
        assert_eq!(
            stacktrace[3].function,
            "Program.<Main>g__f|0_0(System.Func`2[T,TResult] d, System.Int32& l, System.Int32 m)".to_string()
        );
        assert_eq!(stacktrace[4].address, 139758385041658);
        assert_eq!(stacktrace[4].function, "Program.Main()".to_string());

        let sttr = CSharpStacktrace::parse_stacktrace(&trace);

        assert!(sttr.is_err());
        assert_eq!(sttr.err().unwrap().to_string(), "Casr: Couldn't parse stacktrace line: at A`1[T].<set_Q>g__g|1_0 (System.Int32[] arr) <0x40b745f0 + 0x00122> in /home/user/mono/2/src/2.cs:13");
    }
}
