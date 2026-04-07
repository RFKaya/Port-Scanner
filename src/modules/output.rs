//! Result Formatter for Terminal Output
//!
//! Renders scan results as formatted markdown tables or JSON for the CLI.
//! Integrates vulnerability remediation advice, IP classification, and
//! banner grabbing results.

use crate::modules::network;
use crate::modules::vuln_db;
use crate::persistence::models::{OutputFormat, PortStatus, ScanResult};
use crate::scanner::banner::BannerResult;
use std::fmt::Write;

/// Print scan results to stdout in the selected format.
pub fn print_results(result: &ScanResult, format: &OutputFormat) {
    match format {
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(&result) {
                println!("{json}");
            } else {
                eprintln!("Failed to serialize results to JSON.");
            }
        }
        OutputFormat::Md => {
            println!("{}", render_markdown(result));
        }
    }
}

/// Print banner grabbing results to stdout.
pub fn print_banner_results(results: &[BannerResult]) {
    if results.is_empty() {
        return;
    }

    println!("\n\x1b[1;35m┌──────────────────────────────────────────────────┐\x1b[0m");
    println!("\x1b[1;35m│           SERVICE BANNER RESULTS                 │\x1b[0m");
    println!("\x1b[1;35m├──────┬────────────────────┬───────────────────────┤\x1b[0m");
    println!(
        "\x1b[1;35m│\x1b[0m \x1b[1mPort\x1b[0m \x1b[1;35m│\x1b[0m \x1b[1mService\x1b[0m            \x1b[1;35m│\x1b[0m \x1b[1mBanner\x1b[0m                \x1b[1;35m│\x1b[0m"
    );
    println!("\x1b[1;35m├──────┼────────────────────┼───────────────────────┤\x1b[0m");

    for br in results {
        let service = br.service_name.as_deref().unwrap_or("Unknown");
        let version = br.service_version.as_deref().unwrap_or("");
        let service_str = if version.is_empty() {
            service.to_string()
        } else {
            format!("{service} {version}")
        };

        let banner_preview: String = br
            .raw_banner
            .as_deref()
            .unwrap_or("-")
            .chars()
            .take(21)
            .collect();

        println!(
            "\x1b[1;35m│\x1b[0m {:<4} \x1b[1;35m│\x1b[0m {:<18} \x1b[1;35m│\x1b[0m {:<21} \x1b[1;35m│\x1b[0m",
            br.port, service_str, banner_preview
        );
    }

    println!("\x1b[1;35m└──────┴────────────────────┴───────────────────────┘\x1b[0m");
}

/// Render a full markdown report from scan results.
///
/// Includes a summary table, detailed findings with vulnerability info,
/// remediation advice, and IP classification context.
pub fn render_markdown(result: &ScanResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Scan Results for Target: {}\n", result.target);

    // IP Classification
    if let Ok(ip) = result.target.parse::<std::net::IpAddr>() {
        let classification = network::classify_ip(&ip);
        let is_private = network::is_private_ip(&ip);
        let _ = writeln!(
            out,
            "> **Network Type:** {} | **Private:** {}\n",
            classification, is_private
        );
    }

    // Count open/closed/filtered using model helpers
    let total = result.ports.len();
    let open = result.open_count();
    let closed = result.closed_count();
    let filtered = result.filtered_count();

    out.push_str("## Summary\n");
    let _ = writeln!(out, "- **Total Ports Scanned:** {total}");
    let _ = writeln!(out, "- **Open:** {open}");
    let _ = writeln!(out, "- **Closed:** {closed}");
    let _ = writeln!(out, "- **Filtered:** {filtered}");
    let _ = writeln!(out, "- **Risk Level:** {}\n", result.max_risk());

    // Detailed findings: open ports
    out.push_str("## Open Ports\n");
    out.push_str("| Port | Protocol | Status | Vulnerability | Risk |\n");
    out.push_str("|------|----------|--------|---------------|------|\n");
    for p in &result.ports {
        if matches!(p.status, PortStatus::Open) {
            let vuln_name = p
                .vulnerability
                .as_ref()
                .map_or("-".to_string(), |v| v.name.clone());
            let risk = p
                .vulnerability
                .as_ref()
                .map_or("-".to_string(), |v| format!("{}", v.risk));
            let _ = writeln!(
                out,
                "| {} | {} | **{:?}** | {} | {} |",
                p.port, p.protocol, p.status, vuln_name, risk
            );
        }
    }

    if open == 0 {
        out.push_str("| - | - | *No open ports found* | - | - |\n");
    }

    // Vulnerability details and remediation
    let vulnerable_ports = result.vulnerable_ports();
    if !vulnerable_ports.is_empty() {
        let _ = writeln!(out, "\n## Vulnerability Details\n");
        for p in &vulnerable_ports {
            if let Some(ref vuln) = p.vulnerability {
                let _ = writeln!(out, "### Port {} — {} [{}]\n", p.port, vuln.name, vuln.risk);
                let _ = writeln!(out, "{}\n", vuln.description);

                // Add remediation advice from vuln_db
                if let Some(remediation) = vuln_db::get_remediation(p.port) {
                    let _ = writeln!(out, "**Remediation:** {}\n", remediation);
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::models::{
        PortResult, PortStatus, RiskLevel, ScanResult, VulnerabilityInfo,
    };

    #[test]
    fn test_render_markdown_summary() {
        let result = ScanResult {
            target: "localhost".to_string(),
            ports: vec![
                PortResult {
                    port: 80,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Open,
                    vulnerability: None,
                },
                PortResult {
                    port: 443,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Closed,
                    vulnerability: None,
                },
            ],
        };
        let md = render_markdown(&result);
        assert!(md.contains("- **Open:** 1"));
        assert!(md.contains("- **Closed:** 1"));
        assert!(md.contains("| 80 | TCP | **Open** |"));
    }

    #[test]
    fn test_render_markdown_no_open() {
        let result = ScanResult {
            target: "localhost".to_string(),
            ports: vec![PortResult {
                port: 80,
                protocol: "TCP".to_string(),
                status: PortStatus::Closed,
                vulnerability: None,
            }],
        };
        let md = render_markdown(&result);
        assert!(md.contains("- **Open:** 0"));
        assert!(md.contains("*No open ports found*"));
    }

    #[test]
    fn test_render_markdown_with_vulnerability() {
        let result = ScanResult {
            target: "localhost".to_string(),
            ports: vec![PortResult {
                port: 23,
                protocol: "TCP".to_string(),
                status: PortStatus::Open,
                vulnerability: Some(VulnerabilityInfo {
                    risk: RiskLevel::Critical,
                    name: "Telnet Cleartext".to_string(),
                    description: "Telnet is insecure".to_string(),
                }),
            }],
        };
        let md = render_markdown(&result);
        assert!(md.contains("Vulnerability Details"));
        assert!(md.contains("Telnet Cleartext"));
        assert!(md.contains("Critical"));
        assert!(md.contains("Remediation"));
    }

    #[test]
    fn test_render_markdown_with_ip_classification() {
        let result = ScanResult {
            target: "127.0.0.1".to_string(),
            ports: vec![],
        };
        let md = render_markdown(&result);
        assert!(md.contains("Network Type:"));
        assert!(md.contains("Loopback"));
    }

    #[test]
    fn test_render_markdown_risk_level() {
        let result = ScanResult {
            target: "localhost".to_string(),
            ports: vec![PortResult {
                port: 22,
                protocol: "TCP".to_string(),
                status: PortStatus::Open,
                vulnerability: Some(VulnerabilityInfo {
                    risk: RiskLevel::Low,
                    name: "SSH".to_string(),
                    description: "SSH Access".to_string(),
                }),
            }],
        };
        let md = render_markdown(&result);
        assert!(md.contains("Risk Level:"));
    }

    #[test]
    fn test_print_banner_results_empty() {
        // Should not panic with empty results
        print_banner_results(&[]);
    }

    #[test]
    fn test_print_banner_results_with_data() {
        let results = vec![BannerResult {
            port: 22,
            raw_banner: Some("SSH-2.0-OpenSSH_8.9".to_string()),
            service_name: Some("SSH".to_string()),
            service_version: Some("2.0-OpenSSH_8.9".to_string()),
            probe_used: crate::scanner::banner::ProbeType::Passive,
        }];
        // Should not panic
        print_banner_results(&results);
    }
}
