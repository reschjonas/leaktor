use std::collections::HashMap;

/// Analyzer for calculating Shannon entropy of strings
pub struct EntropyAnalyzer;

impl EntropyAnalyzer {
    /// Calculate Shannon entropy of a string
    pub fn calculate(text: &str) -> f64 {
        if text.is_empty() {
            return 0.0;
        }

        let mut frequency: HashMap<char, usize> = HashMap::new();
        let length = text.len() as f64;

        // Count character frequencies
        for ch in text.chars() {
            *frequency.entry(ch).or_insert(0) += 1;
        }

        // Calculate entropy using Shannon formula: -Σ(p(x) * log2(p(x)))
        let mut entropy = 0.0;
        for &count in frequency.values() {
            let probability = count as f64 / length;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    /// Check if a string has high entropy (likely random/secret)
    pub fn is_high_entropy(text: &str, threshold: f64) -> bool {
        Self::calculate(text) >= threshold
    }

    /// Analyze entropy for different character sets
    pub fn analyze_detailed(text: &str) -> EntropyAnalysis {
        let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let hex_chars = "0123456789abcdefABCDEF";

        let total_entropy = Self::calculate(text);
        let is_base64_like = text
            .chars()
            .all(|c| base64_chars.contains(c) || c.is_whitespace());
        let is_hex_like = text.chars().all(|c| hex_chars.contains(c));

        EntropyAnalysis {
            entropy: total_entropy,
            is_high_entropy: total_entropy >= 4.0,
            is_base64_like,
            is_hex_like,
            length: text.len(),
        }
    }

    /// Calculate entropy for base64-like strings
    pub fn base64_entropy(text: &str) -> f64 {
        let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let filtered: String = text.chars().filter(|c| base64_chars.contains(*c)).collect();
        Self::calculate(&filtered)
    }

    /// Calculate entropy for hex strings
    pub fn hex_entropy(text: &str) -> f64 {
        let hex_chars = "0123456789abcdefABCDEF";
        let filtered: String = text.chars().filter(|c| hex_chars.contains(*c)).collect();
        Self::calculate(&filtered)
    }
}

#[derive(Debug, Clone)]
pub struct EntropyAnalysis {
    pub entropy: f64,
    pub is_high_entropy: bool,
    pub is_base64_like: bool,
    pub is_hex_like: bool,
    pub length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_low() {
        let text = "aaaaaaaaaa";
        let entropy = EntropyAnalyzer::calculate(text);
        assert!(entropy < 1.0);
    }

    #[test]
    fn test_entropy_high() {
        let text = "aB3$xY9#mK2@";
        let entropy = EntropyAnalyzer::calculate(text);
        assert!(entropy > 3.0);
    }

    #[test]
    fn test_entropy_medium() {
        let text = "password123";
        let entropy = EntropyAnalyzer::calculate(text);
        assert!(entropy > 2.0 && entropy < 4.0);
    }

    #[test]
    fn test_is_high_entropy() {
        // Test with realistic threshold (3.5 is default in config)
        assert!(EntropyAnalyzer::is_high_entropy("Xy9#mK2@qL5&", 3.5));
        assert!(EntropyAnalyzer::is_high_entropy("aB3$xY9#mK2@qL5&pN7!", 4.0));
        assert!(!EntropyAnalyzer::is_high_entropy("password", 4.0));
    }

    #[test]
    fn test_base64_detection() {
        let analysis = EntropyAnalyzer::analyze_detailed("SGVsbG8gV29ybGQ=");
        assert!(analysis.is_base64_like);
    }

    #[test]
    fn test_hex_detection() {
        let analysis = EntropyAnalyzer::analyze_detailed("deadbeef1234567890abcdef");
        assert!(analysis.is_hex_like);
    }
}
