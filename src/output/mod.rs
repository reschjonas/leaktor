pub mod console;
pub mod html;
pub mod json;
pub mod sarif;

pub use console::ConsoleOutput;
pub use html::HtmlOutput;
pub use json::JsonOutput;
pub use sarif::SarifOutput;

use crate::models::Finding;
use anyhow::Result;
use std::path::Path;

/// Trait for output formatters
pub trait OutputFormatter {
    fn format(&self, findings: &[Finding]) -> Result<String>;
    fn write_to_file(&self, findings: &[Finding], path: &Path) -> Result<()>;
}
