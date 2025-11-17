pub mod filesystem;
pub mod git;

pub use filesystem::FilesystemScanner;
pub use git::GitScanner;

use crate::models::Finding;
use anyhow::Result;

/// Common trait for all scanners
pub trait Scanner {
    fn scan(&self) -> Result<Vec<Finding>>;
}
