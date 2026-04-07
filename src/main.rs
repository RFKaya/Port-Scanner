mod config;
mod error;
mod modules;
mod persistence;
mod scanner;
mod server;

pub use crate::error::{AppError, Result};

use crate::modules::{network, output, parser, stats, vuln_db};
use crate::persistence::models::{OutputFormat, PortResult, ScanResult, ScanType};
use crate::scanner::{banner, tcp_connect, tcp_syn, udp};
use clap::{Args as ClapArgs, Parser, Subcommand};
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

// CLI structure defining the top-level commands
#[derive(Parser, Debug)]
#[command(name = "secops", version = "1.7.1", about = "Security Operations Tool")]
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

    /// Enable banner grabbing on open ports
    #[arg(long)]
    banner: bool,
}

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    let _ = dotenvy::dotenv().ok();

    // Initialize the tracing subscriber for logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Load and validate application configuration
    let app_config = config::AppConfig::from_env();
    if let Err(errors) = app_config.validate() {
        for err in &errors {
            tracing::warn!("Configuration warning: {err}");
        }
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Pentest { tool } => match tool {
            PentestCommands::PortScan(args) => {
                // Validate port input before starting the scan
                if let Err(e) = parser::validate_port_input(&args.range) {
                    tracing::error!("Invalid port range: {e}");
                    return;
                }

                // Resolve and classify the target
                let target_spec = match parser::parse_target(&args.target) {
                    Ok(spec) => spec,
                    Err(e) => {
                        tracing::error!("Target resolution failed: {e}");
                        return;
                    }
                };

                let ip_class = network::classify_ip(&target_spec.ip);
                let port_count = parser::estimate_port_count(&args.range);

                // Print scan header
                println!(
                    "\x1b[1;34m========================================================\x1b[0m"
                );
                println!(
                    "\x1b[1;32m   🛡️  SecOps Port Scanner — CLI Scan Started          \x1b[0m"
                );
                println!(
                    "\x1b[1;34m========================================================\x1b[0m"
                );
                println!("\x1b[1;36m   🎯 Target:  \x1b[1;33m{}\x1b[0m", target_spec);
                println!("\x1b[1;36m   🌐 Network: \x1b[1;33m{}\x1b[0m", ip_class);
                println!(
                    "\x1b[1;36m   📡 Ports:   \x1b[1;33m{} ({})\x1b[0m",
                    args.range, port_count
                );
                println!(
                    "\x1b[1;36m   ⏱️  Timeout: \x1b[1;33m{}ms\x1b[0m",
                    args.timeout
                );
                println!(
                    "\x1b[1;36m   🔌 Banner:  \x1b[1;33m{}\x1b[0m",
                    if args.banner { "Enabled" } else { "Disabled" }
                );
                println!(
                    "\x1b[1;34m========================================================\x1b[0m"
                );

                // Warn if scanning a public IP
                if matches!(ip_class, network::IpClassification::Public) {
                    tracing::warn!(
                        "Scanning a public IP address ({}). Ensure you have authorization.",
                        target_spec.ip
                    );
                }

                tracing::info!(
                    "Starting {} scan on {} ({}) — {} ports, timeout {}ms",
                    if args.syn {
                        "SYN"
                    } else if args.udp {
                        "UDP"
                    } else {
                        "TCP"
                    },
                    target_spec,
                    ip_class,
                    port_count,
                    args.timeout
                );

                // Start timing
                let scan_start = Instant::now();

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
                    Ok(mut data) => {
                        let scan_duration = scan_start.elapsed();

                        // Banner grabbing phase (if enabled)
                        if args.banner {
                            let open_ports: Vec<u16> = data
                                .ports
                                .iter()
                                .filter(|p| p.is_open())
                                .map(|p| p.port)
                                .collect();

                            if !open_ports.is_empty() {
                                println!(
                                    "\n\x1b[1;36m🔍 Grabbing banners for {} open port(s)...\x1b[0m",
                                    open_ports.len()
                                );
                                let banner_results =
                                    grab_banners(target_spec.ip, &open_ports, args.timeout).await;
                                output::print_banner_results(&banner_results);
                            }
                        }

                        // Build and display statistics
                        let scan_stats = stats::build_statistics(&data, scan_duration);
                        let report = stats::generate_summary_report(&scan_stats);
                        println!("\n{report}");

                        // Print detailed results
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

/// Grab banners from a list of open ports.
///
/// Runs banner grabbing concurrently with a small concurrency limit.
async fn grab_banners(target: IpAddr, ports: &[u16], timeout_ms: u64) -> Vec<banner::BannerResult> {
    let mut results = Vec::new();
    let semaphore = Arc::new(Semaphore::new(10)); // Limit concurrent banner grabs

    let handles: Vec<_> = ports
        .iter()
        .map(|&port| {
            let sem = Arc::clone(&semaphore);
            let timeout = Some(timeout_ms);
            tokio::spawn(async move {
                let _permit = sem.acquire().await;
                banner::grab_banner(target, port, timeout).await
            })
        })
        .collect();

    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    results.sort_by_key(|r| r.port);
    results
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

    // Parse target using the parser module
    let Ok(target_ip) = parser::resolve_target(&target) else {
        return stream::empty().boxed();
    };

    // Parse port range using the parser module
    let range_to_use = if range.is_empty() { "1-1024" } else { &range };
    let ports = parser::parse_ports(range_to_use);

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
    // Check target resolution first using the parser module
    let _ = parser::resolve_target(&target)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single() {
        assert_eq!(parser::parse_ports("80"), vec![80]);
    }

    #[test]
    fn test_parse_ports_range() {
        assert_eq!(parser::parse_ports("1-5"), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_ports_mixed() {
        assert_eq!(
            parser::parse_ports("80,443,10-12"),
            vec![10, 11, 12, 80, 443]
        );
    }

    #[test]
    fn test_parse_ports_overlap_and_unsorted() {
        assert_eq!(
            parser::parse_ports("80,70-85,22"),
            vec![22, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85]
        );
    }

    #[test]
    fn test_parse_ports_invalid() {
        assert_eq!(parser::parse_ports("abc, 70000, -1"), Vec::<u16>::new());
    }

    #[test]
    fn test_resolve_target_ip() {
        assert!(parser::resolve_target("127.0.0.1").is_ok());
        assert!(parser::resolve_target("::1").is_ok());
    }

    #[test]
    fn test_resolve_target_localhost() {
        assert!(parser::resolve_target("localhost").is_ok());
    }

    #[test]
    fn test_effective_concurrency_tcp() {
        assert_eq!(effective_concurrency(&ScanType::Connect, 5000), 2000);
        assert_eq!(effective_concurrency(&ScanType::Connect, 100), 100);
        assert_eq!(effective_concurrency(&ScanType::Connect, 0), 1);
    }

    #[test]
    fn test_effective_concurrency_syn() {
        assert_eq!(effective_concurrency(&ScanType::Syn, 500), 200);
        assert_eq!(effective_concurrency(&ScanType::Syn, 50), 50);
    }

    #[test]
    fn test_effective_concurrency_udp() {
        assert_eq!(effective_concurrency(&ScanType::Udp, 1000), 500);
        assert_eq!(effective_concurrency(&ScanType::Udp, 200), 200);
    }

    #[test]
    fn test_validate_port_input_integration() {
        assert!(parser::validate_port_input("1-1024").is_ok());
        assert!(parser::validate_port_input("").is_err());
        assert!(parser::validate_port_input("99999").is_err());
    }

    #[test]
    fn test_ip_classification_integration() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            network::classify_ip(&ip),
            network::IpClassification::Loopback
        );

        let public_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(
            network::classify_ip(&public_ip),
            network::IpClassification::Public
        );
    }

    #[test]
    fn test_config_from_env_integration() {
        let cfg = config::AppConfig::from_env();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.scan.default_timeout_ms, 1000);
    }
}
