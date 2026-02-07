pub mod filesystem;
pub mod git;
pub mod multiformat;
pub mod stdin;

pub use filesystem::FilesystemScanner;
pub use git::GitScanner;
pub use multiformat::{detect_format, scan_structured_file, StructuredFormat};
pub use stdin::StdinScanner;

use crate::models::Finding;
use anyhow::Result;

/// Common trait for all scanners
pub trait Scanner {
    fn scan(&self) -> Result<Vec<Finding>>;
}
