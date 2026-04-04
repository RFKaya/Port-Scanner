use crate::models::{OutputFormat, PortStatus, ScanResult};

pub fn print_results(result: &ScanResult, format: &OutputFormat) {
    match format {
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(&result) {
                println!("{}", json);
            } else {
                eprintln!("Failed to serialize results to JSON.");
            }
        }
        OutputFormat::Md => {
            println!("{}", render_markdown(result));
        }
    }
}

pub fn render_markdown(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Scan Results for Target: {}\n\n", result.target));

    // Count open/closed/filtered
    let total = result.ports.len();
    let open = result
        .ports
        .iter()
        .filter(|p| matches!(p.status, PortStatus::Open))
        .count();
    let closed = result
        .ports
        .iter()
        .filter(|p| matches!(p.status, PortStatus::Closed))
        .count();
    let filtered = result
        .ports
        .iter()
        .filter(|p| matches!(p.status, PortStatus::Filtered))
        .count();

    out.push_str("## Summary\n");
    out.push_str(&format!("- **Total Ports Scanned:** {}\n", total));
    out.push_str(&format!("- **Open:** {}\n", open));
    out.push_str(&format!("- **Closed:** {}\n", closed));
    out.push_str(&format!("- **Filtered:** {}\n\n", filtered));

    out.push_str("## Detailed Findings\n");
    out.push_str("| Port | Protocol | Status |\n");
    out.push_str("|------|----------|--------|\n");
    for p in &result.ports {
        if matches!(p.status, PortStatus::Open) {
            out.push_str(&format!(
                "| {} | {} | **{:?}** |\n",
                p.port, p.protocol, p.status
            ));
        }
    }

    if open == 0 {
        out.push_str("| - | - | *No open ports found* |\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{PortResult, PortStatus, ScanResult};

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
}
