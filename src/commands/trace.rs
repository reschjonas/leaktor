use anyhow::Result;
use colored::*;
use leaktor::*;
use std::path::PathBuf;

pub fn trace_command(
    query: Option<String>,
    secret_type: Option<String>,
    file: Option<PathBuf>,
    path: PathBuf,
) -> Result<()> {
    if query.is_none() && secret_type.is_none() && file.is_none() {
        anyhow::bail!(
            "{} Provide a secret value, --type, or --file to trace.\n{} Examples:\n  leaktor trace AKIAZ52HGX...\n  leaktor trace --type \"AWS Access Key\"\n  leaktor trace --file .env",
            "Error:".red().bold(),
            "Hint:".yellow().bold()
        );
    }

    println!("{}", "Blast Radius Analysis".bold());
    println!();

    // Step 1: Identify secrets to trace
    let mut search_terms: Vec<(String, String)> = Vec::new(); // (label, value_or_pattern)

    if let Some(ref q) = query {
        search_terms.push(("Query".to_string(), q.clone()));
    }

    if let Some(ref file_path) = file {
        // Scan the specified file to extract secrets
        let content = std::fs::read_to_string(file_path)?;
        let detector = leaktor::detectors::PatternDetector::new();
        for line in content.lines() {
            let matches = detector.scan_line(line, 3.0);
            for m in matches {
                let label = format!("{} (from {})", m.secret_type.as_str(), file_path.display());
                search_terms.push((label, m.value.clone()));
            }
        }
        if search_terms.is_empty() {
            println!(
                "  {} No secrets found in {}",
                "[!]".yellow(),
                file_path.display()
            );
            return Ok(());
        }
    }

    // Step 2: Scan the codebase for all findings
    let scanner = FilesystemScanner::new(path.clone()).with_entropy_threshold(3.0);
    let all_findings = scanner.scan()?;

    // Step 3: For type-based search, find matching findings
    if let Some(ref type_name) = secret_type {
        let type_lower = type_name.to_lowercase();
        let matching: Vec<_> = all_findings
            .iter()
            .filter(|f| {
                f.secret
                    .secret_type
                    .as_str()
                    .to_lowercase()
                    .contains(&type_lower)
            })
            .collect();

        if matching.is_empty() {
            println!(
                "  {} No findings of type \"{}\" in this codebase",
                "[OK]".green(),
                type_name
            );
            return Ok(());
        }

        // Group by unique secret value
        let mut unique_values: std::collections::HashMap<String, Vec<&leaktor::Finding>> =
            std::collections::HashMap::new();
        for f in &matching {
            unique_values
                .entry(f.secret.value.clone())
                .or_default()
                .push(f);
        }

        println!(
            "  Found {} unique {} secret(s) across {} location(s)",
            unique_values.len().to_string().yellow().bold(),
            type_name.cyan(),
            matching.len().to_string().yellow()
        );
        println!();

        for (i, (value, locations)) in unique_values.iter().enumerate() {
            let display_val = if value.len() > 20 {
                format!("{}...{}", &value[..8], &value[value.len() - 4..])
            } else {
                value.clone()
            };
            println!(
                "  Secret #{}: {} ({} reference{})",
                i + 1,
                display_val.red(),
                locations.len(),
                if locations.len() == 1 { "" } else { "s" }
            );
            for loc in locations {
                println!(
                    "    {} {}:{}",
                    "->".dimmed(),
                    loc.location.file_path.display(),
                    loc.location.line_number
                );
            }
            println!();
        }

        return Ok(());
    }

    // Step 4: For value-based search, search for the string across all files
    for (label, search_value) in &search_terms {
        println!(
            "  {} Tracing: {} ({})",
            "[*]".dimmed(),
            &search_value[..search_value.len().min(20)],
            label
        );
        println!();

        // Search all text files for this value
        let mut reference_files: Vec<(PathBuf, usize, String)> = Vec::new();

        // Exclude common scan output files from trace results
        let output_extensions: &[&str] = &["sarif", "html"];
        let output_filenames: &[&str] = &[
            "report.html",
            "leaktor-report.html",
            "results.json",
            "results.sarif",
            "scan.json",
            "scan-results.json",
            "leaktor-results.json",
        ];

        let walker = ignore::WalkBuilder::new(&path)
            .git_ignore(true)
            .hidden(false)
            .build();

        for entry in walker.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }

            // Skip known scan output files
            let file_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if output_filenames.contains(&file_name) {
                continue;
            }
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if output_extensions.contains(&ext) {
                    continue;
                }
            }

            if let Ok(content) = std::fs::read_to_string(p) {
                // Detect leaktor JSON output by schema signature (first 300 chars)
                if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    let header: String = content.chars().take(300).collect();
                    if header.contains("\"version\"")
                        && header.contains("\"total_findings\"")
                        && header.contains("\"findings\"")
                    {
                        continue;
                    }
                }
                for (line_num, line) in content.lines().enumerate() {
                    if line.contains(search_value.as_str()) {
                        reference_files.push((
                            p.to_path_buf(),
                            line_num + 1,
                            line.trim().to_string(),
                        ));
                    }
                }
            }
        }

        if reference_files.is_empty() {
            println!("    {} No references found in the codebase", "[OK]".green());
        } else {
            println!(
                "    {} {} reference(s) found:",
                "[!]".yellow(),
                reference_files.len().to_string().red().bold()
            );
            println!();
            for (file_path, line_num, line_content) in &reference_files {
                let display_line = if line_content.len() > 80 {
                    format!("{}...", &line_content[..77])
                } else {
                    line_content.clone()
                };
                println!("    {} {}:{}", "->".dimmed(), file_path.display(), line_num);
                println!("      {}", display_line.dimmed());
            }
        }
        println!();
    }

    // Step 5: Show blast radius summary
    if let Some(ref q) = query {
        // Check if this value appears in common sensitive locations
        let sensitive_patterns = [
            (
                "Environment files",
                vec![".env", ".env.local", ".env.production"],
            ),
            (
                "Config files",
                vec![".toml", ".yaml", ".yml", ".json", ".ini", ".conf"],
            ),
            (
                "CI/CD",
                vec![
                    "Jenkinsfile",
                    "Dockerfile",
                    ".github/",
                    ".gitlab-ci",
                    ".circleci",
                ],
            ),
            (
                "Infrastructure",
                vec![".tf", ".tfvars", "docker-compose", "k8s", "helm"],
            ),
        ];

        let mut blast_summary: Vec<(&str, usize)> = Vec::new();
        let walker = ignore::WalkBuilder::new(&path)
            .git_ignore(true)
            .hidden(false)
            .build();

        for entry in walker.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let path_str = p.to_string_lossy().to_lowercase();
            if let Ok(content) = std::fs::read_to_string(p) {
                if content.contains(q.as_str()) {
                    for (category, patterns) in &sensitive_patterns {
                        if patterns.iter().any(|pat| path_str.contains(pat)) {
                            if let Some(entry) =
                                blast_summary.iter_mut().find(|(c, _)| c == category)
                            {
                                entry.1 += 1;
                            } else {
                                blast_summary.push((category, 1));
                            }
                        }
                    }
                }
            }
        }

        if !blast_summary.is_empty() {
            println!("{}", "  Blast Radius Summary".bold().underline());
            for (category, count) in &blast_summary {
                let severity_color = if *count > 3 {
                    "[!!]"
                } else if *count > 1 {
                    "[!]"
                } else {
                    "[-]"
                };
                println!(
                    "    {} {} ({} file{})",
                    severity_color,
                    category,
                    count,
                    if *count == 1 { "" } else { "s" }
                );
            }
            println!();
        }
    }

    Ok(())
}
