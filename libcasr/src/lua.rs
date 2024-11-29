//! Lua module implements `ParseStacktrace`, `CrashLineExt` and `Severity` traits for Lua reports.
use crate::error::*;
use crate::execution_class::ExecutionClass;
use crate::severity::Severity;
use crate::stacktrace::{CrashLine, CrashLineExt, DebugInfo};
use crate::stacktrace::{ParseStacktrace, Stacktrace, StacktraceEntry};

use regex::Regex;

/// Structure provides an interface for save parsing lua exception.
#[derive(Clone, Debug)]
pub struct LuaException {
    message: String,
}

impl LuaException {
    /// Create new `LuaException` instance from stream
    pub fn new(stream: &str) -> Option<Self> {
        let re = Regex::new(r#"\S+: .+\n\s*stack traceback:\s*\n(?:.*\n)*.+: .+"#).unwrap();
        let mat = re.find(stream)?;
        Some(LuaException {
            message: mat.as_str().to_string(),
        })
    }
    /// Extract stack trace from lua exception.
    pub fn extract_stacktrace(&self) -> Result<Vec<String>> {
        LuaStacktrace::extract_stacktrace(&self.message)
    }
    /// Transform lua exception into `Stacktrace` type.
    pub fn parse_stacktrace(&self) -> Result<Stacktrace> {
        LuaStacktrace::parse_stacktrace(&self.extract_stacktrace()?)
    }
    /// Get lua exception as a vector of lines.
    pub fn lua_report(&self) -> Vec<String> {
        self.message
            .split('\n')
            .map(|s| s.trim().to_string())
            .collect()
    }
}

/// Structure provides an interface for processing the stack trace.
pub struct LuaStacktrace;

impl ParseStacktrace for LuaStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let stacktrace = stream
            .split('\n')
            .map(|l| l.trim().to_string())
            .collect::<Vec<String>>();
        let Some(first) = stacktrace
            .iter()
            .position(|line| line.ends_with("stack traceback:"))
        else {
            return Err(Error::Casr(
                "Couldn't find traceback in lua report".to_string(),
            ));
        };

        let re = Regex::new(r#".+: in .+"#).unwrap();
        Ok(stacktrace[first..]
            .iter()
            .map(|s| s.to_string())
            .filter(|s| re.is_match(s))
            .collect::<Vec<String>>())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let mut stentry = StacktraceEntry::default();
        let re = Regex::new(r#"(.+):(\d+): in (\S+ )(\S+)"#).unwrap();
        let Some(cap) = re.captures(entry) else {
            return Err(Error::Casr(format!(
                "Couldn't parse stacktrace line: {entry}"
            )));
        };
        stentry.debug.file = cap.get(1).unwrap().as_str().to_string();
        if let Ok(line) = cap.get(2).unwrap().as_str().parse::<u64>() {
            stentry.debug.line = line;
        } else {
            return Err(Error::Casr(format!(
                "Couldn't parse stacktrace line number: {entry}"
            )));
        };
        stentry.function = if let Some(func) = cap.get(4) {
            func.as_str()
                .to_string()
                .trim_matches('\'')
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_string()
        } else {
            return Err(Error::Casr(format!(
                "Couldn't parse stacktrace function: {entry}"
            )));
        };
        if let Some(appendix) = cap.get(3) {
            let appendix = appendix.as_str().to_string();
            if appendix.starts_with("main") {
                stentry.function = appendix + &stentry.function;
            }
        }
        Ok(stentry)
    }

    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        let mut stacktrace = Stacktrace::new();
        for entry in entries.iter() {
            if entry.starts_with("[C]:") {
                continue;
            }
            stacktrace.push(Self::parse_stacktrace_entry(entry)?);
        }
        Ok(stacktrace)
    }
}

impl CrashLineExt for LuaException {
    fn crash_line(&self) -> Result<CrashLine> {
        let lines = self.lua_report();
        let re = Regex::new(r#"\S+: (.+):(\d+):"#).unwrap();
        let mut cap = re.captures(&lines[0]);
        if cap.is_none() {
            let Some(index) = lines
                .iter()
                .rposition(|line| line.ends_with("stack traceback:"))
            else {
                return Err(Error::Casr(
                    "Couldn't find traceback in lua report".to_string(),
                ));
            };
            let re = Regex::new(r#"(.+):(\d+):"#).unwrap();
            for line in &lines[index + 1..] {
                cap = re.captures(line);
                if cap.is_some() {
                    break;
                }
            }
        }
        let Some(cap) = cap else {
            return Err(Error::Casr(format!("Crashline is not found: {:?}", lines)));
        };
        let file = cap.get(1).unwrap().as_str().to_string();
        let line = cap.get(2).unwrap().as_str();
        let Ok(line) = line.parse::<u64>() else {
            return Err(Error::Casr(format!(
                "Couldn't crashline line number: {line}"
            )));
        };
        Ok(CrashLine::Source(DebugInfo {
            file,
            line,
            column: 0,
        }))
    }
}

impl Severity for LuaException {
    fn severity(&self) -> Result<ExecutionClass> {
        let re = Regex::new(r#"\S+:(?: .+:)? (.+)"#).unwrap();
        let lines = self.lua_report();
        let description = lines.first().unwrap();
        let Some(cap) = re.captures(description) else {
            return Err(Error::Casr(format!(
                "Couldn't parse exception description: {description}"
            )));
        };
        let description = cap.get(1).unwrap().as_str().to_string();
        Ok(ExecutionClass::new((
            "NOT_EXPLOITABLE",
            &description,
            "",
            "",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lua_exception() {
        let stream = "
            lua: (error object is a table value)
            stack traceback:
              [C]: in function 'error'
              /usr/local/share/lua/5.4/luacheck/parser.lua:28: in function 'luacheck.parser.syntax_error'
              /usr/local/share/lua/5.4/luacheck/parser.lua:96: in upvalue 'parse_error'
              /usr/local/share/lua/5.4/luacheck/parser.lua:535: in upvalue 'parse_simple_expression'
              /usr/local/share/lua/5.4/luacheck/parser.lua:894: in function </usr/local/share/lua/5.4/luacheck/parser.lua:886>
              (...tail calls...)
              /usr/local/share/lua/5.4/luacheck/parser.lua:974: in upvalue 'parse_block'
              /usr/local/share/lua/5.4/luacheck/parser.lua:1020: in function 'luacheck.parser.parse'
              luacheck_parser_parse.lua:6: in local 'TestOneInput'
              luacheck_parser_parse.lua:18: in main chunk
              [C]: in ?
        ";
        let exception = LuaException::new(stream);
        let Some(exception) = exception else {
            panic!("{:?}", exception);
        };

        let lines = exception.lua_report();
        assert_eq!(lines.len(), 13);

        let sttr = exception.extract_stacktrace();
        let Ok(sttr) = sttr else {
            panic!("{}", sttr.err().unwrap());
        };
        assert_eq!(sttr.len(), 10);

        let sttr = exception.parse_stacktrace();
        let Ok(sttr) = sttr else {
            panic!("{}", sttr.err().unwrap());
        };
        assert_eq!(sttr.len(), 8);
        assert_eq!(
            sttr[0].debug.file,
            "/usr/local/share/lua/5.4/luacheck/parser.lua".to_string()
        );
        assert_eq!(sttr[0].debug.line, 28);
        assert_eq!(sttr[0].function, "luacheck.parser.syntax_error".to_string());
        assert_eq!(
            sttr[1].debug.file,
            "/usr/local/share/lua/5.4/luacheck/parser.lua".to_string()
        );
        assert_eq!(sttr[1].debug.line, 96);
        assert_eq!(sttr[1].function, "parse_error".to_string());
        assert_eq!(
            sttr[2].debug.file,
            "/usr/local/share/lua/5.4/luacheck/parser.lua".to_string()
        );
        assert_eq!(sttr[2].debug.line, 535);
        assert_eq!(sttr[2].function, "parse_simple_expression".to_string());
        assert_eq!(
            sttr[3].debug.file,
            "/usr/local/share/lua/5.4/luacheck/parser.lua".to_string()
        );
        assert_eq!(sttr[3].debug.line, 894);
        assert_eq!(
            sttr[3].function,
            "/usr/local/share/lua/5.4/luacheck/parser.lua:886".to_string()
        );
        assert_eq!(
            sttr[4].debug.file,
            "/usr/local/share/lua/5.4/luacheck/parser.lua".to_string()
        );
        assert_eq!(sttr[4].debug.line, 974);
        assert_eq!(sttr[4].function, "parse_block".to_string());
        assert_eq!(
            sttr[5].debug.file,
            "/usr/local/share/lua/5.4/luacheck/parser.lua".to_string()
        );
        assert_eq!(sttr[5].debug.line, 1020);
        assert_eq!(sttr[5].function, "luacheck.parser.parse".to_string());
        assert_eq!(sttr[6].debug.file, "luacheck_parser_parse.lua".to_string());
        assert_eq!(sttr[6].debug.line, 6);
        assert_eq!(sttr[6].function, "TestOneInput".to_string());
        assert_eq!(sttr[7].debug.file, "luacheck_parser_parse.lua".to_string());
        assert_eq!(sttr[7].debug.line, 18);
        assert_eq!(sttr[7].function, "main chunk".to_string());

        let crashline = exception.crash_line();
        let Ok(crashline) = crashline else {
            panic!("{}", crashline.err().unwrap());
        };
        assert_eq!(
            crashline.to_string(),
            "/usr/local/share/lua/5.4/luacheck/parser.lua:28"
        );

        let execution_class = exception.severity();
        let Ok(execution_class) = execution_class else {
            panic!("{}", execution_class.err().unwrap());
        };
        assert_eq!(execution_class.severity, "NOT_EXPLOITABLE");
        assert_eq!(
            execution_class.short_description,
            "(error object is a table value)"
        );
        assert_eq!(execution_class.description, "");
        assert_eq!(execution_class.explanation, "");

        let stream = "
            custom-lua-interpreter: (command line):1: crash
            stack traceback:
                some custom error message
            stack traceback: 
                [C]: in function 'error'
                (command line):1: in main chunk
                [C]: at 0x607f3df872e0
        ";
        let exception = LuaException::new(stream);
        let Some(exception) = exception else {
            panic!("{:?}", exception);
        };

        let lines = exception.lua_report();
        assert_eq!(lines.len(), 7);

        let sttr = exception.extract_stacktrace();
        let Ok(sttr) = sttr else {
            panic!("{}", sttr.err().unwrap());
        };
        assert_eq!(sttr.len(), 2);

        let sttr = exception.parse_stacktrace();
        let Ok(sttr) = sttr else {
            panic!("{}", sttr.err().unwrap());
        };
        assert_eq!(sttr.len(), 1);
        assert_eq!(sttr[0].debug.file, "(command line)".to_string());
        assert_eq!(sttr[0].debug.line, 1);
        assert_eq!(sttr[0].function, "main chunk".to_string());

        let crashline = exception.crash_line();
        let Ok(crashline) = crashline else {
            panic!("{}", crashline.err().unwrap());
        };
        assert_eq!(crashline.to_string(), "(command line):1");

        let execution_class = exception.severity();
        let Ok(execution_class) = execution_class else {
            panic!("{}", execution_class.err().unwrap());
        };
        assert_eq!(execution_class.severity, "NOT_EXPLOITABLE");
        assert_eq!(execution_class.short_description, "crash");
        assert_eq!(execution_class.description, "");
        assert_eq!(execution_class.explanation, "");
    }
}
