//! Provides `Severity` trait.
use crate::error::*;
use crate::execution_class::ExecutionClass;

/// Severity determination trait
pub trait Severity {
    /// Get severity class and return it as a `ExecutionClass` struct
    fn severity(&self) -> Result<ExecutionClass>;
}
