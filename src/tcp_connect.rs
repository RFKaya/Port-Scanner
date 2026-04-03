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
            vulnerability: None,
        },
        Ok(Err(_e)) => PortResult {
            port,
            protocol: "TCP".to_string(),
            status: PortStatus::Closed,
            vulnerability: None,
        },
        Err(_) => PortResult {
            port,
            protocol: "TCP".to_string(),
            status: PortStatus::Filtered,
            vulnerability: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_scan_port_open() {
        // Start a listener on a random available port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();

        let result = scan_port(addr.ip(), port, Duration::from_millis(500)).await;
        assert!(matches!(result.status, PortStatus::Open));
    }

    #[tokio::test]
    async fn test_scan_port_closed() {
        // Use a port that is unlikely to be open
        let result = scan_port(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 54321, Duration::from_millis(100)).await;
        // Depending on the OS, this might be Closed or Filtered (if there's a firewall)
        // On localhost, it's almost always Closed.
        assert!(matches!(result.status, PortStatus::Closed | PortStatus::Filtered));
    }
}
