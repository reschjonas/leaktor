pub mod git;
pub mod filesystem;

pub use git::GitScanner;
pub use filesystem::FilesystemScanner;

use crate::models::Finding;
use anyhow::Result;

/// Common trait for all scanners
pub trait Scanner {
    fn scan(&self) -> Result<Vec<Finding>>;
}
