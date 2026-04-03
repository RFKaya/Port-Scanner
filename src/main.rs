mod models;
mod output;
mod tcp_connect;
mod tcp_syn;
mod udp;

use clap::{Parser, Subcommand, Args as ClapArgs};
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use crate::models::{OutputFormat, PortResult, ScanResult, ScanType};

#[derive(Parser, Debug)]
#[command(name = "secops", version, about = "Security Operations Tool")]
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
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Pentest { tool } => match tool {
            PentestCommands::PortScan(args) => run_port_scan(args).await,
        },
    }
}

async fn run_port_scan(args: ScanArgs) {
    // Determine scan type based on flags
    let scan_type = if args.syn {
        ScanType::Syn
    } else if args.udp {
        ScanType::Udp
    } else {
        ScanType::Connect // Default
    };

    // Parse target
    let target_ip = resolve_target(&args.target);
    if target_ip.is_none() {
        eprintln!("Failed to resolve target: {}", args.target);
        std::process::exit(1);
    }
    let target_ip = target_ip.unwrap();

    // Parse port range
    let ports = parse_ports(&args.range);

    // Timeout duration
    let timeout_dur = Duration::from_millis(args.timeout);

    // Parallel stream for scanning
    let concurrency_limit = 500;

    let scan_stream = stream::iter(ports).map(|port| {
        let st = scan_type.clone();
        async move {
            match st {
                ScanType::Connect => tcp_connect::scan_port(target_ip, port, timeout_dur).await,
                ScanType::Syn => tcp_syn::scan_port(target_ip, port, timeout_dur).await,
                ScanType::Udp => udp::scan_port(target_ip, port, timeout_dur).await,
            }
        }
    }).buffer_unordered(concurrency_limit);

    // Collect results
    let mut results: Vec<PortResult> = scan_stream.collect().await;

    // Sort by port
    results.sort_by(|a, b| a.port.cmp(&b.port));

    let scan_res = ScanResult {
        target: args.target.clone(),
        ports: results,
    };

    output::print_results(&scan_res, &args.format);
}

// Simple port range parser. Handles "80" or "1-1024".
fn parse_ports(range_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    let parts: Vec<&str> = range_str.split('-').collect();
    if parts.len() == 2 {
        let start: u16 = parts[0].parse().unwrap_or(1);
        let end: u16 = parts[1].parse().unwrap_or(1024);
        for p in start..=end {
            ports.push(p);
        }
    } else if parts.len() == 1 {
        if let Ok(p) = parts[0].parse() {
            ports.push(p);
        }
    }
    ports
}

// Simple DNS lookup / IP parser
fn resolve_target(target: &str) -> Option<IpAddr> {
    // If it's directly an IP
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Some(ip);
    }
    
    // Otherwise, try to resolve via ToSocketAddrs
    // We append a dummy port just for resolution
    let probe = format!("{}:80", target);
    if let Ok(mut addrs) = probe.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Some(addr.ip());
        }
    }
    None
}
