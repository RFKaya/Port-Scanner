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
            println!("# Scan Results for Target: {}", result.target);
            println!();
            
            // Count open/closed/filtered
            let total = result.ports.len();
            let open = result.ports.iter().filter(|p| matches!(p.status, PortStatus::Open)).count();
            let closed = result.ports.iter().filter(|p| matches!(p.status, PortStatus::Closed)).count();
            let filtered = result.ports.iter().filter(|p| matches!(p.status, PortStatus::Filtered)).count();
            
            println!("## Summary");
            println!("- **Total Ports Scanned:** {}", total);
            println!("- **Open:** {}", open);
            println!("- **Closed:** {}", closed);
            println!("- **Filtered:** {}", filtered);
            println!();
            println!("## Detailed Findings");
            println!("| Port | Protocol | Status |");
            println!("|------|----------|--------|");
            for p in &result.ports {
                if matches!(p.status, PortStatus::Open) {
                    println!("| {} | {} | **{:?}** |", p.port, p.protocol, p.status);
                }
            }
            
            // Note: Printing closed/filtered could be excessively long, so we only print OPEN ports in detail
            // but if there are none, we add a notification.
            if open == 0 {
                println!("| - | - | *No open ports found* |");
            }
        }
    }
}
