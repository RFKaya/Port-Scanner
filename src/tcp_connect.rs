use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::models::{PortResult, PortStatus};

/// Perform a full TCP connect scan on a given port.
pub async fn scan_port(target: IpAddr, port: u16, timeout_dur: Duration) -> PortResult {
    let socket_addr = std::net::SocketAddr::new(target, port);
    
    // Attempt to connect with a timeout
    match timeout(timeout_dur, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(_stream)) => PortResult {
            port,
            protocol: "TCP".to_string(),
            status: PortStatus::Open,
        },
        Ok(Err(_e)) => PortResult {
            // Connection refused or comparable error
            port,
            protocol: "TCP".to_string(),
            status: PortStatus::Closed,
        },
        Err(_) => PortResult {
            // Timeout means we likely got silently dropped (Filtered)
            port,
            protocol: "TCP".to_string(),
            status: PortStatus::Filtered,
        },
    }
}
