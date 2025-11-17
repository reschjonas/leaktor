use super::{Secret, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Location information for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file_path: PathBuf,
    pub line_number: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub commit_hash: Option<String>,
    pub commit_author: Option<String>,
    pub commit_date: Option<DateTime<Utc>>,
}

/// Context around the finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    pub line_before: Option<String>,
    pub line_content: String,
    pub line_after: Option<String>,
    pub is_test_file: bool,
    pub is_config_file: bool,
    pub is_documentation: bool,
    pub file_extension: Option<String>,
}

/// A complete finding with secret and location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub secret: Secret,
    pub location: Location,
    pub context: Context,
    pub timestamp: DateTime<Utc>,
    pub ignored: bool,
    pub ignore_reason: Option<String>,
}

impl Finding {
    pub fn new(secret: Secret, location: Location, context: Context) -> Self {
        Self {
            id: Uuid::new_v4(),
            secret,
            location,
            context,
            timestamp: Utc::now(),
            ignored: false,
            ignore_reason: None,
        }
    }

    pub fn severity(&self) -> Severity {
        self.secret.severity
    }

    pub fn is_likely_false_positive(&self) -> bool {
        // Lower confidence or test files are more likely false positives
        self.secret.confidence < 0.7 || self.context.is_test_file || self.context.is_documentation
    }
}
