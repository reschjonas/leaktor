pub mod json;
pub mod sarif;
pub mod html;
pub mod console;

pub use json::JsonOutput;
pub use sarif::SarifOutput;
pub use html::HtmlOutput;
pub use console::ConsoleOutput;

use crate::models::Finding;
use anyhow::Result;
use std::path::Path;

/// Trait for output formatters
pub trait OutputFormatter {
    fn format(&self, findings: &[Finding]) -> Result<String>;
    fn write_to_file(&self, findings: &[Finding], path: &Path) -> Result<()>;
}
