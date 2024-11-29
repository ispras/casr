//! Lua module implements `ParseStacktrace`, `Exception` traits for Lua reports.
use crate::error::*;
use crate::exception::Exception;
use crate::execution_class::ExecutionClass;
use crate::severity::Severity;
use crate::stacktrace::{CrashLine, CrashLineExt, DebugInfo};
use crate::stacktrace::{ParseStacktrace, Stacktrace, StacktraceEntry};

use regex::Regex;

/// Structure provides an interface for processing the stack trace.
pub struct LuaStacktrace;

impl ParseStacktrace for LuaStacktrace {
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>> {
        let stacktrace = stream
            .split('\n')
            .map(|l| l.to_string())
            .collect::<Vec<String>>();
        let Some(first) = stacktrace
            .iter()
            .position(|line| line.trim().starts_with("stack traceback:"))
        else {
            return Err(Error::Casr(
                "Couldn't find traceback in lua report".to_string(),
            ));
        };

        let re = Regex::new(r#"\S+:(?:|\d+:) in .+"#).unwrap();
        Ok(stacktrace[first..]
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| re.is_match(s))
            .collect::<Vec<String>>())
    }

    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry> {
        let mut stentry = StacktraceEntry::default();
        let re = Regex::new(r#"(\S+):(\d+): in (\S+ )(\S+)"#).unwrap();
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
            if !appendix.starts_with("function")
                && !appendix.starts_with("upvalue")
                && !appendix.starts_with("local")
            {
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

/// Structure provides an interface for parsing lua exception message.
pub struct LuaException;
impl Exception for LuaException {
    fn parse_exception(stderr: &str) -> Option<ExecutionClass> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lua_stacktrace() {
        let raw_stacktrace = "
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
        let sttr = LuaStacktrace::extract_stacktrace(raw_stacktrace);
        let Ok(sttr) = sttr else {
            panic!("{}", sttr.err().unwrap());
        };
        assert_eq!(sttr.len(), 10);

        let sttr = LuaStacktrace::parse_stacktrace(&sttr);
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
    }
}
