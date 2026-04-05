mod error;
mod models;
mod output;
mod server;
mod tcp_connect;
mod tcp_syn;
mod udp;
mod vuln_db;

pub use crate::error::{AppError, Result};

use crate::models::{OutputFormat, PortResult, ScanResult, ScanType};
use clap::{Args as ClapArgs, Parser, Subcommand};
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "secops", version = "1.5.0", about = "Security Operations Tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Penetration testing tools
    Pentest {
        #[command(subcommand)]
        tool: PentestCommands,
    },
    /// Start the web UI server
    Web {
        #[arg(long, default_value = "3000")]
        port: u16,
    },
}

#[derive(Subcommand, Debug)]
enum PentestCommands {
    /// Port scanning tool
    PortScan(ScanArgs),
}

#[derive(ClapArgs, Debug)]
struct ScanArgs {
    /// Target IP or hostname
    #[arg(required = true)]
    target: String,

    /// Port range (e.g., 1-1024)
    #[arg(long, default_value = "1-1024")]
    range: String,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Md)]
    format: OutputFormat,

    /// TCP Connect Scan (Default)
    #[arg(long, group = "protocol")]
    tcp: bool,

    /// TCP SYN Scan (Requires Admin)
    #[arg(long, group = "protocol")]
    syn: bool,

    /// UDP Scan
    #[arg(long, group = "protocol")]
    udp: bool,

    /// Timeout in milliseconds per port
    #[arg(long, default_value_t = 1000)]
    timeout: u64,

    /// Number of concurrent tasks (default: 500)
    #[arg(short = 'c', long, default_value_t = 500)]
    concurrency: usize,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pentest { tool } => match tool {
            PentestCommands::PortScan(args) => {
                let res = run_port_scan_logic(
                    args.target.clone(),
                    args.range.clone(),
                    args.syn,
                    args.udp,
                    args.timeout,
                    args.concurrency,
                )
                .await;

                match res {
                    Ok(data) => output::print_results(&data, &args.format),
                    Err(e) => eprintln!("Error: {e}"),
                }
            }
        },
        Commands::Web { port } => server::start_server(port).await,
    }
}

#[allow(clippy::unused_async)]
pub async fn run_port_scan_logic_stream(
    target: String,
    range: String,
    syn: bool,
    udp: bool,
    timeout_ms: u64,
    concurrency_limit: usize,
) -> futures::stream::BoxStream<'static, PortResult> {
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    // Determine scan type
    let scan_type = if syn {
        ScanType::Syn
    } else if udp {
        ScanType::Udp
    } else {
        ScanType::Connect
    };

    // Parse target
    let Ok(target_ip) = resolve_target(&target) else {
        return stream::empty().boxed();
    };

    // Parse port range
    let range_to_use = if range.is_empty() { "1-1024" } else { &range };
    let ports = parse_ports(range_to_use);

    // Timeout duration
    let timeout_dur = Duration::from_millis(timeout_ms);

    let (tx, rx) = mpsc::channel(100);

    tokio::spawn(async move {
        let scan_stream = stream::iter(ports)
            .map(|port| {
                let st = scan_type.clone();
                let tx_inner = tx.clone();
                async move {
                    let mut res = match st {
                        ScanType::Connect => {
                            tcp_connect::scan_port(target_ip, port, timeout_dur).await
                        }
                        ScanType::Syn => tcp_syn::scan_port(target_ip, port, timeout_dur).await,
                        ScanType::Udp => udp::scan_port(target_ip, port, timeout_dur).await,
                    };

                    // If port is open, check for known vulnerabilities
                    if matches!(res.status, crate::models::PortStatus::Open) {
                        res.vulnerability = vuln_db::get_vuln_for_port(port);
                    }

                    let _ = tx_inner.send(res).await;
                }
            })
            .buffer_unordered(concurrency_limit);

        scan_stream.collect::<()>().await;
    });

    ReceiverStream::new(rx).boxed()
}

/// Scans the target for open ports based on the provided range and parameters.
///
/// # Errors
///
/// Returns an error if the target hostname cannot be resolved to an IP address.
pub async fn run_port_scan_logic(
    target: String,
    range: String,
    syn: bool,
    udp: bool,
    timeout_ms: u64,
    concurrency: usize,
) -> Result<ScanResult> {
    // Check target resolution first
    let _ = resolve_target(&target)?;

    let mut stream =
        run_port_scan_logic_stream(target.clone(), range, syn, udp, timeout_ms, concurrency).await;
    let mut results = Vec::new();
    while let Some(res) = stream.next().await {
        results.push(res);
    }
    // Final sort for CLI/Legacy
    results.sort_by(|a, b| a.port.cmp(&b.port));
    Ok(ScanResult {
        target,
        ports: results,
    })
}

// Simple port range parser. Handles "80", "1-1024", or "80,443,1-100".
fn parse_ports(range_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in range_str.split(',') {
        let part_str = part.trim();
        if part_str.is_empty() {
            continue;
        }

        let sub_parts: Vec<&str> = part_str.split('-').collect();
        if sub_parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (sub_parts[0].parse::<u32>(), sub_parts[1].parse::<u32>())
            {
                // Clamp to valid port ranges
                let start_clamped = start.clamp(1, 65535) as u16;
                let end_clamped = end.clamp(1, 65535) as u16;

                for p in start_clamped..=end_clamped {
                    ports.push(p);
                }
            }
        } else if sub_parts.len() == 1 {
            if let Ok(p) = sub_parts[0].parse::<u32>() {
                if (1..=65535).contains(&p) {
                    if let Ok(p_u16) = u16::try_from(p) {
                        ports.push(p_u16);
                    }
                }
            }
        }
    }
    // Remove duplicates
    ports.sort_unstable();
    ports.dedup();

    ports
}

// Simple DNS lookup / IP parser
fn resolve_target(target: &str) -> crate::Result<IpAddr> {
    // If it's directly an IP
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Otherwise, try to resolve via ToSocketAddrs
    // We append a dummy port just for resolution
    let probe = format!("{target}:80");
    if let Ok(mut addrs) = probe.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(addr.ip());
        }
    }
    Err(AppError::Resolution(target.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single() {
        assert_eq!(parse_ports("80"), vec![80]);
    }

    #[test]
    fn test_parse_ports_range() {
        assert_eq!(parse_ports("1-5"), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_ports_mixed() {
        assert_eq!(parse_ports("80,443,10-12"), vec![10, 11, 12, 80, 443]);
    }

    #[test]
    fn test_parse_ports_overlap_and_unsorted() {
        assert_eq!(
            parse_ports("80,70-85,22"),
            vec![22, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85]
        );
    }

    #[test]
    fn test_parse_ports_invalid() {
        assert_eq!(parse_ports("abc, 70000, -1"), Vec::<u16>::new());
    }

    #[test]
    fn test_resolve_target_ip() {
        assert!(resolve_target("127.0.0.1").is_ok());
        assert!(resolve_target("::1").is_ok());
    }

    #[test]
    fn test_resolve_target_localhost() {
        // This might fail in some restricted environments, but usually works
        assert!(resolve_target("localhost").is_ok());
    }
}
