pub mod filesystem;
pub mod git;
pub mod multiformat;
pub mod stdin;

#[cfg(feature = "docker")]
pub mod docker;
#[cfg(feature = "s3")]
pub mod s3;

pub use filesystem::FilesystemScanner;
pub use git::GitScanner;
pub use multiformat::{detect_format, scan_structured_file, StructuredFormat};
pub use stdin::StdinScanner;

#[cfg(feature = "docker")]
pub use docker::DockerScanner;
#[cfg(feature = "s3")]
pub use s3::S3Scanner;

use crate::models::Finding;
use anyhow::Result;

/// Common trait for all scanners
pub trait Scanner {
    fn scan(&self) -> Result<Vec<Finding>>;
}
