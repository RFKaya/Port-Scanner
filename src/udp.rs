use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::models::{PortResult, PortStatus};

/// Perform a basic UDP scan on a given port.
pub async fn scan_port(target: IpAddr, port: u16, timeout_dur: Duration) -> PortResult {
    // Bind to a local ephemeral port
    let local_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = match UdpSocket::bind(local_addr).await {
        Ok(s) => s,
        Err(_) => return PortResult {
            port,
            protocol: "UDP".to_string(),
            status: PortStatus::Filtered, // Assume something blocked local bind
            vulnerability: None,
        },
    };

    let target_addr = std::net::SocketAddr::new(target, port);
    if socket.connect(&target_addr).await.is_err() {
         return PortResult { port, protocol: "UDP".to_string(), status: PortStatus::Closed, vulnerability: None };
    }

    // Send an empty UDP payload. Some services might not respond to empty payloads,
    // but this is a simple scanner.
    let buf = [0u8; 0];
    if socket.send(&buf).await.is_err() {
        return PortResult { port, protocol: "UDP".to_string(), status: PortStatus::Closed, vulnerability: None };
    }

    // Try to receive a response
    let mut recv_buf = [0u8; 1024];
    match timeout(timeout_dur, socket.recv(&mut recv_buf)).await {
        Ok(Ok(_len)) => {
            // We received a reply! Port is definitely open
            PortResult {
                port,
                protocol: "UDP".to_string(),
                status: PortStatus::Open,
                vulnerability: None,
            }
        },
        Ok(Err(_)) => {
            // Error receiving, typically ICMP port unreachable mapped to connection refused
            PortResult {
                port,
                protocol: "UDP".to_string(),
                status: PortStatus::Closed,
                vulnerability: None,
            }
        },
        Err(_) => {
            // Timeout. Port might be Open or Filtered.
            // Often interpreted as Open|Filtered. We will report it as Filtered for simplicity.
            PortResult {
                port,
                protocol: "UDP".to_string(),
                status: PortStatus::Filtered,
                vulnerability: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_scan_port_udp_listener() {
        // Start a UDP listener on a random port
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        
        // Scan the port
        let result = scan_port(addr.ip(), addr.port(), Duration::from_millis(100)).await;
        // In many UDP implementations, a simple send/recv might still result in Filtered 
        // if no response is received, but let's see what the current logic does.
        assert!(matches!(result.status, PortStatus::Open | PortStatus::Filtered));
    }

    #[tokio::test]
    async fn test_scan_port_udp_closed() {
        // Scan a port that is unlikely to have anything
        let result = scan_port(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 54322, Duration::from_millis(50)).await;
        assert!(matches!(result.status, PortStatus::Closed | PortStatus::Filtered));
    }
}
