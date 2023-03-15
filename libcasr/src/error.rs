//! A custom Casr error.
use std::fmt;
use std::io;
use std::result;

use thiserror::Error;

#[derive(Error, Debug)]
/// A custom Casr error
pub enum Error {
    /// An IO based error
    IO(io::Error),
    /// gdb-command error
    GdbCommand(gdb_command::error::Error),
    /// Casr error (any analysis or report error)
    Casr(String),
    /// Goblin error
    #[cfg(feature = "exploitable")]
    Goblin(goblin::error::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IO(ref err) => write!(f, "{err}"),
            Error::GdbCommand(ref err) => write!(f, "{err}"),
            Error::Casr(ref msg) => write!(f, "Casr: {msg}"),
            #[cfg(feature = "exploitable")]
            Error::Goblin(ref msg) => write!(f, "Goblin: {msg}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<gdb_command::error::Error> for Error {
    fn from(err: gdb_command::error::Error) -> Error {
        Error::GdbCommand(err)
    }
}

#[cfg(feature = "exploitable")]
impl From<goblin::error::Error> for Error {
    fn from(err: goblin::error::Error) -> Error {
        Error::Goblin(err)
    }
}

pub type Result<T> = result::Result<T, Error>;
