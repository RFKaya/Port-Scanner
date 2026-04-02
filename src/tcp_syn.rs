use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol};
use tokio::task;

use crate::models::{PortResult, PortStatus};

/// Perform a TCP SYN scan on a given port (Requires Administrator/root privileges).
/// Because `pnet` uses blocking sockets, we wrap it in a blocking task.
pub async fn scan_port(target: IpAddr, port: u16, timeout_dur: Duration) -> PortResult {
    task::spawn_blocking(move || {
        scan_port_blocking(target, port, timeout_dur)
    }).await.unwrap_or_else(|_| PortResult {
        port,
        protocol: "TCP-SYN.ERR".to_string(),
        status: PortStatus::Filtered,
    })
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
            }
        }
    };

    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));

    // Create a transport channel (requires privileges)
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(_) => {
            // Permission denied or Npcap missing
            return PortResult {
                port,
                protocol: "TCP-SYN".to_string(),
                status: PortStatus::Filtered, // Or Permission Denied state
            };
        }
    };

    let mut packet = [0u8; 20];
    let mut tcp_packet = MutableTcpPacket::new(&mut packet).unwrap();

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
    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &dummy_sys_ip, &target_v4);
    tcp_packet.set_checksum(checksum);

    // Send packet
    if tx.send_to(tcp_packet, target).is_err() {
        return PortResult { port, protocol: "TCP-SYN".to_string(), status: PortStatus::Filtered };
    }

    let mut rx_iter = tcp_packet_iter(&mut rx);
    let start = std::time::Instant::now();

    // Wait for response
    loop {
        if start.elapsed() > timeout_dur {
            return PortResult { port, protocol: "TCP-SYN".to_string(), status: PortStatus::Filtered };
        }

        // We use next_with_timeout to avoid blocking forever
        match rx_iter.next_with_timeout(timeout_dur - start.elapsed()) {
            Ok(Some((resp_packet, _addr))) => {
                // Check if this response is for our probe
                if resp_packet.get_destination() == source_port && resp_packet.get_source() == port {
                    let flags = resp_packet.get_flags();
                    if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                        return PortResult { port, protocol: "TCP-SYN".to_string(), status: PortStatus::Open };
                    } else if flags & TcpFlags::RST == TcpFlags::RST {
                        return PortResult { port, protocol: "TCP-SYN".to_string(), status: PortStatus::Closed };
                    }
                }
            },
            _ => continue,
        }
    }
}
