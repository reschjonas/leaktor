//! Lightweight diagnostic infrastructure for surfacing non-fatal warnings.
//!
//! Instead of silently swallowing errors (e.g. unreadable files, unparseable
//! commits), code should call [`warn`] or use the [`scan_warn!`] macro to
//! record them.  Warnings are:
//!
//! 1. Printed to stderr immediately (for interactive users).
//! 2. Collected in a thread-safe global list so they can be included in
//!    structured output (JSON/SARIF) or shown in a summary.
//!
//! # Usage
//!
//! ```ignore
//! use crate::diagnostics;
//!
//! // Simple message
//! diagnostics::warn("git", &format!("could not open repo: {}", err));
//!
//! // Or use the macro
//! scan_warn!("fs", "could not read {}: {}", path.display(), err);
//! ```

use std::sync::Mutex;

/// A single diagnostic warning emitted during a scan.
#[derive(Debug, Clone)]
pub struct Warning {
    /// Short category tag (e.g. "git", "fs", "parse", "validate").
    pub category: String,
    /// Human-readable message describing what went wrong.
    pub message: String,
}

// ── Global collector ──────────────────────────────────────────────────────

static WARNINGS: Mutex<Vec<Warning>> = Mutex::new(Vec::new());

/// Record a warning. Prints to stderr and stores for later retrieval.
pub fn warn(category: &str, message: &str) {
    let w = Warning {
        category: category.to_string(),
        message: message.to_string(),
    };

    // Print to stderr immediately so interactive users see it.
    // Use a format that stands out but doesn't look like a hard error.
    eprintln!(
        "\x1b[33m[warn:{}]\x1b[0m {}",
        w.category, w.message
    );

    if let Ok(mut warnings) = WARNINGS.lock() {
        warnings.push(w);
    }
}

/// Retrieve and drain all collected warnings.
pub fn take_warnings() -> Vec<Warning> {
    if let Ok(mut warnings) = WARNINGS.lock() {
        std::mem::take(&mut *warnings)
    } else {
        Vec::new()
    }
}

/// Return the number of warnings collected so far (without draining).
pub fn warning_count() -> usize {
    if let Ok(warnings) = WARNINGS.lock() {
        warnings.len()
    } else {
        0
    }
}

/// Clear all collected warnings (useful between test runs).
#[cfg(test)]
pub fn clear() {
    if let Ok(mut warnings) = WARNINGS.lock() {
        warnings.clear();
    }
}

/// Convenience macro: `scan_warn!("category", "format string {}", args...)`
#[macro_export]
macro_rules! scan_warn {
    ($cat:expr, $($arg:tt)*) => {
        $crate::diagnostics::warn($cat, &format!($($arg)*))
    };
}
