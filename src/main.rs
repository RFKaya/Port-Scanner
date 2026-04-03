mod models;
mod output;
mod tcp_connect;
mod tcp_syn;
mod udp;
mod server;

use clap::{Parser, Subcommand, Args as ClapArgs};
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use crate::models::{OutputFormat, PortResult, ScanResult, ScanType};

#[derive(Parser, Debug)]
#[command(name = "secops", version = "1.2.1", about = "Security Operations Tool")]
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
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Pentest { tool } => match tool {
            PentestCommands::PortScan(args) => {
                let res = run_port_scan_logic(args.target.clone(), args.range.clone(), args.syn, args.udp, args.timeout).await;
                output::print_results(&res, &args.format);
            },
        },
        Commands::Web { port } => server::start_server(port).await,
    }
}

pub async fn run_port_scan_logic_stream(target: String, range: String, syn: bool, udp: bool, timeout_ms: u64) -> futures::stream::BoxStream<'static, PortResult> {
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
    let target_ip = resolve_target(&target);
    if target_ip.is_none() {
        return stream::empty().boxed();
    }
    let target_ip = target_ip.unwrap();

    // Parse port range
    let range_to_use = if range.is_empty() { "1-1024" } else { &range };
    let ports = parse_ports(range_to_use);

    // Timeout duration
    let timeout_dur = Duration::from_millis(timeout_ms);
    let concurrency_limit = 500;

    let (tx, rx) = mpsc::channel(100);

    tokio::spawn(async move {
        let scan_stream = stream::iter(ports).map(|port| {
            let st = scan_type.clone();
            let tx_inner = tx.clone();
            async move {
                let res = match st {
                    ScanType::Connect => tcp_connect::scan_port(target_ip, port, timeout_dur).await,
                    ScanType::Syn => tcp_syn::scan_port(target_ip, port, timeout_dur).await,
                    ScanType::Udp => udp::scan_port(target_ip, port, timeout_dur).await,
                };
                let _ = tx_inner.send(res).await;
            }
        }).buffer_unordered(concurrency_limit);
        
        scan_stream.collect::<()>().await;
    });

    ReceiverStream::new(rx).boxed()
}

pub async fn run_port_scan_logic(target: String, range: String, syn: bool, udp: bool, timeout_ms: u64) -> ScanResult {
    let mut stream = run_port_scan_logic_stream(target.clone(), range, syn, udp, timeout_ms).await;
    let mut results = Vec::new();
    while let Some(res) = stream.next().await {
        results.push(res);
    }
    // Final sort for CLI/Legacy
    results.sort_by(|a, b| a.port.cmp(&b.port));
    ScanResult { target, ports: results }
}

// Simple port range parser. Handles "80", "1-1024", or "80,443,1-100".
fn parse_ports(range_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in range_str.split(',') {
        let part_str = part.trim();
        if part_str.is_empty() { continue; }
        
        let sub_parts: Vec<&str> = part_str.split('-').collect();
        if sub_parts.len() == 2 {
            let start: u32 = sub_parts[0].parse().unwrap_or(1);
            let end: u32 = sub_parts[1].parse().unwrap_or(65535);
            
            // Clamp to valid port ranges
            let start_clamped = start.max(1).min(65535) as u16;
            let end_clamped = end.max(1).min(65535) as u16;
            
            for p in start_clamped..=end_clamped {
                ports.push(p);
            }
        } else if sub_parts.len() == 1 {
            if let Ok(p) = sub_parts[0].parse::<u32>() {
                if p >= 1 && p <= 65535 {
                    ports.push(p as u16);
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
