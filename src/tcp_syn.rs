use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::task;

use crate::models::{PortResult, PortStatus};

/// Perform a TCP SYN scan on a given port (Requires Administrator/root privileges).
/// Because `pnet` uses blocking sockets, we wrap it in a blocking task.
pub async fn scan_port(target: IpAddr, port: u16, timeout_dur: Duration) -> PortResult {
    match task::spawn_blocking(move || scan_port_blocking(target, port, timeout_dur)).await {
        Ok(res) => res,
        Err(_) => PortResult {
            port,
            protocol: "TCP-SYN.ERR".to_string(),
            status: PortStatus::Filtered,
            vulnerability: None,
        },
    }
}

fn scan_port_blocking(target: IpAddr, port: u16, timeout_dur: Duration) -> PortResult {
    let target_v4 = match target {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => {
            // IPv6 requires Ipv6NextHeaderProtocols and different channels,
            // returning early for simplicity in this PoC.
            return PortResult {
                port,
                protocol: "TCP-SYN (IPv4 Only)".to_string(),
                status: PortStatus::Filtered,
                vulnerability: None,
            };
        }
    };

    let protocol =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));

    // Create a transport channel (requires privileges)
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(_) => {
            // Permission denied or Npcap missing
            return PortResult {
                port,
                protocol: "TCP-SYN".to_string(),
                status: PortStatus::Filtered, // Or Permission Denied state
                vulnerability: None,
            };
        }
    };

    let mut packet = [0u8; 20];
    let mut tcp_packet = match MutableTcpPacket::new(&mut packet) {
        Some(p) => p,
        None => {
            return PortResult {
                port,
                protocol: "TCP-SYN.ERR".to_string(),
                status: PortStatus::Filtered,
                vulnerability: None,
            }
        }
    };

    // Source port is effectively random for stealth scan
    let source_port = 54321 + (port % 10000);
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(port);
    tcp_packet.set_sequence(100);
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);

    // Calculate TCP checksum
    // Note: pnet needs the source IP for checksum, which can be tricky to find automatically on Windows
    // We'll assume a dummy local IP for the checksum just to make the packet valid enough
    // In a production scanner, you'd route table lookup the outbound interface IP.
    let dummy_sys_ip = Ipv4Addr::new(192, 168, 1, 100);
    let checksum =
        pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &dummy_sys_ip, &target_v4);
    tcp_packet.set_checksum(checksum);

    // Send packet
    if tx.send_to(tcp_packet, target).is_err() {
        return PortResult {
            port,
            protocol: "TCP-SYN".to_string(),
            status: PortStatus::Filtered,
            vulnerability: None,
        };
    }

    let mut rx_iter = tcp_packet_iter(&mut rx);
    let start = std::time::Instant::now();

    // Wait for response
    loop {
        if start.elapsed() > timeout_dur {
            return PortResult {
                port,
                protocol: "TCP-SYN".to_string(),
                status: PortStatus::Filtered,
                vulnerability: None,
            };
        }

        // We use standard next(). In a blocking queue, this may block until a packet arrives,
        // so timeout might not be instantaneous if the network is completely silent.
        match rx_iter.next() {
            Ok((resp_packet, _addr)) => {
                // Check if this response is for our probe
                if resp_packet.get_destination() == source_port && resp_packet.get_source() == port
                {
                    let flags = resp_packet.get_flags();
                    if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                        return PortResult {
                            port,
                            protocol: "TCP-SYN".to_string(),
                            status: PortStatus::Open,
                            vulnerability: None,
                        };
                    } else if flags & TcpFlags::RST == TcpFlags::RST {
                        return PortResult {
                            port,
                            protocol: "TCP-SYN".to_string(),
                            status: PortStatus::Closed,
                            vulnerability: None,
                        };
                    }
                }
            }
            Err(_) => {
                return PortResult {
                    port,
                    protocol: "TCP-SYN".to_string(),
                    status: PortStatus::Filtered,
                    vulnerability: None,
                }
            }
        }
    }
}
