use crate::util;

use std::fmt;
use std::path::Path;

use anyhow::{Result, bail};

#[derive(Clone, Debug, Default, PartialEq)]
pub enum Mode {
    Csharp,
    Gdb,
    Go,
    Java,
    Js,
    Lua,
    Python,
    Rust,
    #[default]
    San, // Intermediate mode
    Asan,
    Msan,
}

impl Mode {
    pub fn new(mode: &str) -> Result<Mode> {
        match mode {
            "csharp" => Ok(Mode::Csharp),
            "gdb" => Ok(Mode::Gdb),
            "go" => Ok(Mode::Go),
            "java" => Ok(Mode::Java),
            "js" => Ok(Mode::Js),
            "lua" => Ok(Mode::Lua),
            "python" => Ok(Mode::Python),
            "rust" => Ok(Mode::Rust),
            "san" => Ok(Mode::San),
            "asan" => Ok(Mode::Asan),
            "msan" => Ok(Mode::Msan),
            _ => {
                bail!("Unexpected mode: {}", mode);
            }
        }
    }

    pub fn from(name: Option<&str>, argv: &[String]) -> Result<Self> {
        if name.is_some() && name.unwrap() != "auto" {
            Ok(Mode::new(name.unwrap())?)
        } else if argv[0].ends_with("dotnet") || argv[0].ends_with("mono") {
            Ok(Mode::Csharp)
        } else if argv[0].ends_with("jazzer") || argv[0].ends_with("java") {
            Ok(Mode::Java)
        } else if argv[0].ends_with(".js")
            || argv[0].ends_with("node")
            || argv[0].ends_with("jsfuzz")
            || argv.len() > 1 && argv[0].ends_with("npx") && argv[1] == "jazzer"
        {
            Ok(Mode::Js)
        } else if argv[0].ends_with(".lua")
            || argv[0].starts_with("lua")
            || argv.len() > 1 && argv[1].ends_with(".lua")
        {
            Ok(Mode::Lua)
        } else if argv[0].ends_with(".py")
            || argv[0].starts_with("python")
            || argv.len() > 1 && argv[1].ends_with(".py")
        {
            Ok(Mode::Python)
        } else {
            let sym_list = util::symbols_list(Path::new(&argv[0]))?;
            if sym_list.contains("__asan")
                || sym_list.contains("__msan")
                || sym_list.contains("runtime.go")
            {
                // NOTE: The exact mode can only be found out by parsing
                Ok(Mode::San)
            } else {
                Ok(Mode::Gdb)
            }
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Mode::Csharp => "csharp",
            Mode::Gdb => "gdb",
            Mode::Go => "go",
            Mode::Java => "java",
            Mode::Js => "js",
            Mode::Lua => "lua",
            Mode::Python => "python",
            Mode::Rust => "rust",
            Mode::San => "san",
            Mode::Asan => "asan",
            Mode::Msan => "msan",
        };
        write!(f, "{}", s)
    }
}
