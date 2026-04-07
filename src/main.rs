mod error;
mod modules;
mod persistence;
mod scanner;
mod server;

pub use crate::error::{AppError, Result};

use crate::modules::{output, vuln_db};
use crate::persistence::models::{OutputFormat, PortResult, ScanResult, ScanType};
use crate::scanner::{tcp_connect, tcp_syn, udp};
use clap::{Args as ClapArgs, Parser, Subcommand};
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

// CLI structure defining the top-level commands
#[derive(Parser, Debug)]
#[command(name = "secops", version = "1.7.0", about = "Security Operations Tool")]
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
    /// Start the web UI server (Axum-based)
    Web {
        #[arg(long, env = "PORT", default_value = "3000")]
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
    #[arg(short = 'r', long, default_value = "1-1024")]
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

    /// Number of concurrent tasks (Adaptive limits: TCP: 2000, UDP: 500, SYN: 200)
    #[arg(short = 'c', long, default_value_t = 500)]
    concurrency: usize,
}

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    let _ = dotenvy::dotenv().ok();

    // Initialize the tracing subscriber for logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Pentest { tool } => match tool {
            PentestCommands::PortScan(args) => {
                tracing::info!("Starting scan on {} using range {}", args.target, args.range);
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
                    Ok(data) => {
                        // Print results to screen
                        output::print_results(&data, &args.format);

                        // Save results to disk
                        match data.save_to_file() {
                            Ok(path) => tracing::info!("Scan results saved to: {path}"),
                            Err(e) => tracing::error!("Save error: {e}"),
                        }
                    }
                    Err(e) => tracing::error!("Scan error: {e}"),
                }
            }
        },
        // Launch the web server on the specified port
        Commands::Web { port } => server::start_server(port).await,
    }
}

/// Maximum safe concurrency limits per scan type to prevent OS resource exhaustion.
/// TCP Connect opens real OS sockets, SYN uses raw sockets + blocking threads,
/// UDP binds a new socket per port.
const MAX_CONCURRENCY_TCP: usize = 2000;
const MAX_CONCURRENCY_SYN: usize = 200;
const MAX_CONCURRENCY_UDP: usize = 500;

/// Clamps user-provided concurrency to safe limits based on scan type,
/// ensuring the OS doesn't run out of sockets or file descriptors.
fn effective_concurrency(scan_type: &ScanType, requested: usize) -> usize {
    let cap = match scan_type {
        ScanType::Connect => MAX_CONCURRENCY_TCP,
        ScanType::Syn => MAX_CONCURRENCY_SYN,
        ScanType::Udp => MAX_CONCURRENCY_UDP,
    };
    let effective = requested.min(cap).max(1);
    if requested > cap {
        tracing::warn!(
            "Requested concurrency ({}) exceeds safe limit for {:?} scan. Capped to {}.",
            requested,
            scan_type,
            effective
        );
    } else if requested == 0 {
        tracing::warn!("Requested concurrency (0) is invalid. Increased to 1.");
    }
    effective
}

/// Core streaming logic for port scanning.
///
/// Uses a [`Semaphore`] to enforce a hard cap on simultaneously active OS-level
/// connections, preventing socket/file-descriptor exhaustion even when the
/// user specifies very high concurrency values.
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

    // Apply adaptive concurrency cap based on scan type
    let effective_limit = effective_concurrency(&scan_type, concurrency_limit);

    // Parse target
    let Ok(target_ip) = resolve_target(&target) else {
        return stream::empty().boxed();
    };

    // Parse port range
    let range_to_use = if range.is_empty() { "1-1024" } else { &range };
    let ports = parse_ports(range_to_use);

    // Timeout duration
    let timeout_dur = Duration::from_millis(timeout_ms);

    // Size the channel buffer proportionally to concurrency to avoid
    // unnecessary backpressure when many tasks complete at once.
    let channel_buf = (effective_limit * 2).clamp(100, 8192);
    let (tx, rx) = mpsc::channel(channel_buf);

    // A semaphore acts as the true rate-limiter: even though
    // buffer_unordered eagerly polls futures, the semaphore ensures no
    // more than `effective_limit` OS-level operations run simultaneously.
    let semaphore = Arc::new(Semaphore::new(effective_limit));

    tokio::spawn(async move {
        let scan_stream = stream::iter(ports)
            .map(|port| {
                let st = scan_type.clone();
                let tx_inner = tx.clone();
                let sem = Arc::clone(&semaphore);
                async move {
                    // Acquire a permit before opening any OS socket.
                    // This is the key mechanism that prevents resource exhaustion.
                    let _permit = sem.acquire().await;

                    let mut res = match st {
                        ScanType::Connect => {
                            tcp_connect::scan_port(target_ip, port, timeout_dur).await
                        }
                        ScanType::Syn => tcp_syn::scan_port(target_ip, port, timeout_dur).await,
                        ScanType::Udp => udp::scan_port(target_ip, port, timeout_dur).await,
                    };

                    // If port is open, check for known vulnerabilities
                    if matches!(res.status, crate::persistence::models::PortStatus::Open) {
                        res.vulnerability = vuln_db::get_vuln_for_port(port);
                    }

                    let _ = tx_inner.send(res).await;
                    // _permit is dropped here, releasing the semaphore slot
                }
            })
            .buffer_unordered(effective_limit);

        scan_stream.collect::<()>().await;
    });

    ReceiverStream::new(rx).boxed()
}

/// Synchronous wrapper for port scanning logic.
///
/// # Errors
///
/// Returns an error if the target hostname cannot be resolved or if the scan fails.
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
