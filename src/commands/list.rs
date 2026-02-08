use colored::*;
use std::collections::HashMap;

pub fn list_command() {
    println!("{}", "Supported Secret Types".bold().underline());
    println!();

    let patterns = leaktor::detectors::patterns::PATTERNS.iter();

    let mut by_category: HashMap<&str, Vec<String>> = HashMap::new();

    for pattern in patterns {
        let secret_name = pattern.name.as_str();
        let category = if secret_name.contains("AWS") {
            "AWS"
        } else if secret_name.contains("GCP") || secret_name.contains("Firebase") {
            "Google Cloud"
        } else if secret_name.contains("Azure") {
            "Azure"
        } else if secret_name.contains("GitHub") {
            "GitHub"
        } else if secret_name.contains("GitLab") {
            "GitLab"
        } else if secret_name.contains("Private Key") || secret_name.contains("SSH") {
            "Private Keys"
        } else if secret_name.contains("Database")
            || secret_name.contains("Connection")
            || secret_name.contains("PlanetScale")
            || secret_name.contains("Supabase")
        {
            "Databases"
        } else if secret_name.contains("OpenAI")
            || secret_name.contains("Anthropic")
            || secret_name.contains("Cohere")
            || secret_name.contains("HuggingFace")
            || secret_name.contains("Replicate")
        {
            "AI/ML"
        } else if secret_name.contains("NPM")
            || secret_name.contains("PyPI")
            || secret_name.contains("NuGet")
            || secret_name.contains("RubyGems")
            || secret_name.contains("Docker Hub")
        {
            "Package Registries"
        } else if secret_name.contains("Discord")
            || secret_name.contains("Slack")
            || secret_name.contains("Telegram")
        {
            "Communication"
        } else if secret_name.contains("Stripe")
            || secret_name.contains("Shopify")
            || secret_name.contains("Square")
            || secret_name.contains("PayPal")
        {
            "Payment/E-commerce"
        } else if secret_name.contains("Datadog")
            || secret_name.contains("New Relic")
            || secret_name.contains("Sentry")
            || secret_name.contains("Grafana")
            || secret_name.contains("Elastic")
            || secret_name.contains("Algolia")
        {
            "Monitoring/Observability"
        } else if secret_name.contains("CircleCI")
            || secret_name.contains("Travis")
            || secret_name.contains("Vercel")
            || secret_name.contains("Netlify")
            || secret_name.contains("Heroku")
        {
            "CI/CD & Hosting"
        } else if secret_name.contains("Okta")
            || secret_name.contains("Auth0")
            || secret_name.contains("JWT")
            || secret_name.contains("OAuth")
        {
            "Authentication"
        } else if secret_name.contains("Cloudflare")
            || secret_name.contains("DigitalOcean")
            || secret_name.contains("HashiCorp")
            || secret_name.contains("Linear")
            || secret_name.contains("Notion")
            || secret_name.contains("Airtable")
        {
            "Cloud Services"
        } else {
            "Other"
        };

        // Deduplicate within category
        let entries = by_category.entry(category).or_default();
        if !entries.contains(&secret_name.to_string()) {
            entries.push(secret_name.to_string());
        }
    }

    let categories = [
        "AWS",
        "Google Cloud",
        "Azure",
        "GitHub",
        "GitLab",
        "AI/ML",
        "Private Keys",
        "Databases",
        "Package Registries",
        "Communication",
        "Payment/E-commerce",
        "Monitoring/Observability",
        "CI/CD & Hosting",
        "Authentication",
        "Cloud Services",
        "Other",
    ];

    for category in categories {
        if let Some(items) = by_category.get(category) {
            println!("{}", format!("{}:", category).cyan().bold());
            for item in items {
                println!("  - {}", item);
            }
            println!();
        }
    }

    // Deduplicate for unique pattern count
    let mut unique_names: Vec<&str> = leaktor::detectors::patterns::PATTERNS
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    unique_names.sort();
    unique_names.dedup();

    println!(
        "{} {} ({} regex patterns)",
        "Total secret types:".bold(),
        unique_names.len(),
        leaktor::detectors::patterns::PATTERNS.len()
    );
}
