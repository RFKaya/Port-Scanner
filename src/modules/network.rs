//! Network Utilities Module
//!
//! Provides helper functions for common network operations used throughout
//! the scanner. Includes CIDR notation parsing, enhanced DNS resolution,
//! IP address classification, and local network interface discovery.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use serde::{Deserialize, Serialize};

/// Represents a parsed CIDR notation (e.g., `192.168.1.0/24`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrRange {
    /// The network base address.
    pub network: Ipv4Addr,
    /// The prefix length (0–32).
    pub prefix_len: u8,
    /// Total number of host addresses in this range.
    pub host_count: u32,
}

impl fmt::Display for CidrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} ({} hosts)",
            self.network, self.prefix_len, self.host_count
        )
    }
}

impl CidrRange {
    /// Returns an iterator over all usable host IP addresses in this CIDR range.
    /// For ranges larger than /31, the network and broadcast addresses are excluded.
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        let base: u32 = u32::from(self.network);
        let mask: u32 = if self.prefix_len >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        let network_addr = base & mask;
        let broadcast_addr = network_addr | !mask;

        let mut hosts = Vec::new();

        if self.prefix_len >= 31 {
            // /31 and /32 — include all addresses (point-to-point or single host)
            for ip_int in network_addr..=broadcast_addr {
                hosts.push(Ipv4Addr::from(ip_int));
            }
        } else {
            // Normal range: skip network and broadcast addresses
            for ip_int in (network_addr + 1)..broadcast_addr {
                hosts.push(Ipv4Addr::from(ip_int));
            }
        }

        hosts
    }
}

/// Parse a CIDR notation string into a [`CidrRange`].
///
/// # Arguments
///
/// * `cidr` - A string in the form `"A.B.C.D/N"` where N is 0–32.
///
/// # Errors
///
/// Returns a descriptive error string on malformed input.
///
/// # Examples
///
/// ```ignore
/// let range = parse_cidr("192.168.1.0/24").unwrap();
/// assert_eq!(range.host_count, 254);
/// ```
pub fn parse_cidr(cidr: &str) -> Result<CidrRange, String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid CIDR notation: '{cidr}'. Expected format: A.B.C.D/N"
        ));
    }

    let ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| format!("Invalid IP address in CIDR: '{}'", parts[0]))?;

    let prefix_len: u8 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid prefix length: '{}'", parts[1]))?;

    if prefix_len > 32 {
        return Err(format!("Prefix length must be 0-32, got: {prefix_len}"));
    }

    // Calculate the actual network address by applying the mask
    let ip_int: u32 = u32::from(ip);
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    let network_int = ip_int & mask;
    let network = Ipv4Addr::from(network_int);

    // Calculate host count
    let host_count = if prefix_len >= 31 {
        2u32.pow(32 - prefix_len as u32)
    } else {
        2u32.pow(32 - prefix_len as u32) - 2 // Subtract network and broadcast
    };

    Ok(CidrRange {
        network,
        prefix_len,
        host_count,
    })
}

/// IP address classification for security context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpClassification {
    /// Loopback address (127.x.x.x, ::1)
    Loopback,
    /// Private / RFC1918 address (10.x, 172.16–31.x, 192.168.x)
    Private,
    /// Link-local address (169.254.x.x, fe80::)
    LinkLocal,
    /// Multicast address (224.x–239.x)
    Multicast,
    /// Publicly routable address
    Public,
    /// Reserved or documentation address
    Reserved,
}

impl fmt::Display for IpClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpClassification::Loopback => write!(f, "Loopback"),
            IpClassification::Private => write!(f, "Private"),
            IpClassification::LinkLocal => write!(f, "Link-Local"),
            IpClassification::Multicast => write!(f, "Multicast"),
            IpClassification::Public => write!(f, "Public"),
            IpClassification::Reserved => write!(f, "Reserved"),
        }
    }
}

/// Classify an IP address into its network category.
///
/// Useful for security warnings (e.g., warning when scanning public IPs)
/// and for display purposes in the UI and reports.
pub fn classify_ip(ip: &IpAddr) -> IpClassification {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                IpClassification::Loopback
            } else if v6.is_multicast() {
                IpClassification::Multicast
            } else {
                // Simplified IPv6 classification
                let segments = v6.segments();
                if segments[0] == 0xfe80 {
                    IpClassification::LinkLocal
                } else if segments[0] & 0xfe00 == 0xfc00 {
                    IpClassification::Private // Unique local address
                } else {
                    IpClassification::Public
                }
            }
        }
    }
}

/// Classify an IPv4 address into its network category.
fn classify_ipv4(ip: &Ipv4Addr) -> IpClassification {
    let octets = ip.octets();

    // Loopback: 127.0.0.0/8
    if octets[0] == 127 {
        return IpClassification::Loopback;
    }

    // Private ranges (RFC 1918)
    if octets[0] == 10 // 10.0.0.0/8
        || (octets[0] == 172 && (16..=31).contains(&octets[1])) // 172.16.0.0/12
        || (octets[0] == 192 && octets[1] == 168)
    // 192.168.0.0/16
    {
        return IpClassification::Private;
    }

    // Link-local: 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 {
        return IpClassification::LinkLocal;
    }

    // Multicast: 224.0.0.0/4
    if (224..=239).contains(&octets[0]) {
        return IpClassification::Multicast;
    }

    // Reserved ranges
    if octets[0] == 0          // 0.0.0.0/8 — This network
        || octets[0] == 100 && (64..=127).contains(&octets[1]) // 100.64.0.0/10 — CGN
        || (198..=199).contains(&octets[0]) && octets[0] == 198 && octets[1] == 51 && octets[2] == 100 // 198.51.100.0/24 — Documentation
        || octets[0] == 203 && octets[1] == 0 && octets[2] == 113 // 203.0.113.0/24 — Documentation
        || (240..=255).contains(&octets[0])
    // 240.0.0.0/4 — Reserved
    {
        return IpClassification::Reserved;
    }

    IpClassification::Public
}

/// Check if an IP address is a private/non-routable address.
///
/// Convenience wrapper around [`classify_ip`].
pub fn is_private_ip(ip: &IpAddr) -> bool {
    matches!(
        classify_ip(ip),
        IpClassification::Private | IpClassification::Loopback | IpClassification::LinkLocal
    )
}

/// Resolve a hostname to its first IPv4 address, preferring IPv4 over IPv6.
///
/// # Arguments
///
/// * `hostname` - A hostname or IP address string to resolve.
///
/// # Returns
///
/// The resolved IP address, or an error if resolution fails.
pub fn resolve_hostname(hostname: &str) -> Result<IpAddr, String> {
    // If it's directly an IP address, return immediately
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Append dummy port for `ToSocketAddrs` requirement
    let probe = format!("{hostname}:80");
    let addrs = probe
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve '{hostname}': {e}"))?;

    // Prefer IPv4 addresses
    let mut ipv6_fallback: Option<IpAddr> = None;
    for addr in addrs {
        match addr.ip() {
            IpAddr::V4(_) => return Ok(addr.ip()),
            IpAddr::V6(_) => {
                if ipv6_fallback.is_none() {
                    ipv6_fallback = Some(addr.ip());
                }
            }
        }
    }

    // Fall back to IPv6 if no IPv4 found
    ipv6_fallback.ok_or_else(|| format!("No addresses found for '{hostname}'"))
}

/// Expand a target specification into a list of IP addresses.
///
/// Supports:
/// - Single IP address: `"192.168.1.1"`
/// - Hostname: `"google.com"`
/// - CIDR notation: `"192.168.1.0/24"`
///
/// # Returns
///
/// A vector of resolved IP addresses.
pub fn expand_target(target: &str) -> Result<Vec<IpAddr>, String> {
    // Check for CIDR notation
    if target.contains('/') {
        let cidr = parse_cidr(target)?;
        let hosts: Vec<IpAddr> = cidr.hosts().into_iter().map(IpAddr::V4).collect();
        return Ok(hosts);
    }

    // Single host / hostname
    let ip = resolve_hostname(target)?;
    Ok(vec![ip])
}

/// Information about a local network interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Interface name (e.g., "eth0", "Wi-Fi")
    pub name: String,
    /// IP addresses assigned to this interface
    pub addresses: Vec<IpAddr>,
    /// Whether the interface is a loopback interface
    pub is_loopback: bool,
}

impl fmt::Display for NetworkInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addrs: Vec<String> = self.addresses.iter().map(|a| a.to_string()).collect();
        write!(
            f,
            "{}: [{}]{}",
            self.name,
            addrs.join(", "),
            if self.is_loopback { " (loopback)" } else { "" }
        )
    }
}

/// Calculate the subnet mask for a given prefix length.
///
/// # Examples
///
/// ```ignore
/// let mask = prefix_to_mask(24);
/// assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 0));
/// ```
pub fn prefix_to_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask: u32 = u32::MAX << (32 - prefix_len.min(32));
    Ipv4Addr::from(mask)
}

/// Calculate the broadcast address for a given network and prefix.
pub fn broadcast_address(network: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let net_int: u32 = u32::from(network);
    let host_bits = 32u32.saturating_sub(prefix_len as u32);
    let host_mask = if host_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << host_bits) - 1
    };
    Ipv4Addr::from(net_int | host_mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CIDR Parsing ---

    #[test]
    fn test_parse_cidr_24() {
        let cidr = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(cidr.network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(cidr.prefix_len, 24);
        assert_eq!(cidr.host_count, 254);
    }

    #[test]
    fn test_parse_cidr_32() {
        let cidr = parse_cidr("10.0.0.1/32").unwrap();
        assert_eq!(cidr.network, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(cidr.prefix_len, 32);
        assert_eq!(cidr.host_count, 1);
    }

    #[test]
    fn test_parse_cidr_16() {
        let cidr = parse_cidr("172.16.0.0/16").unwrap();
        assert_eq!(cidr.network, Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(cidr.prefix_len, 16);
        assert_eq!(cidr.host_count, 65534);
    }

    #[test]
    fn test_parse_cidr_normalizes_network() {
        // 192.168.1.100/24 should normalize to 192.168.1.0
        let cidr = parse_cidr("192.168.1.100/24").unwrap();
        assert_eq!(cidr.network, Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_parse_cidr_invalid_format() {
        assert!(parse_cidr("192.168.1.0").is_err());
        assert!(parse_cidr("192.168.1.0/33").is_err());
        assert!(parse_cidr("invalid/24").is_err());
        assert!(parse_cidr("").is_err());
    }

    #[test]
    fn test_cidr_hosts_24() {
        let cidr = parse_cidr("192.168.1.0/24").unwrap();
        let hosts = cidr.hosts();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_cidr_hosts_30() {
        let cidr = parse_cidr("10.0.0.0/30").unwrap();
        let hosts = cidr.hosts();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(hosts[1], Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn test_cidr_display() {
        let cidr = parse_cidr("192.168.1.0/24").unwrap();
        let display = format!("{cidr}");
        assert!(display.contains("192.168.1.0/24"));
        assert!(display.contains("254 hosts"));
    }

    // --- IP Classification ---

    #[test]
    fn test_classify_loopback() {
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            IpClassification::Loopback
        );
        assert_eq!(
            classify_ip(&IpAddr::V6("::1".parse().unwrap())),
            IpClassification::Loopback
        );
    }

    #[test]
    fn test_classify_private() {
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            IpClassification::Private
        );
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            IpClassification::Private
        );
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            IpClassification::Private
        );
    }

    #[test]
    fn test_classify_link_local() {
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))),
            IpClassification::LinkLocal
        );
    }

    #[test]
    fn test_classify_multicast() {
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))),
            IpClassification::Multicast
        );
    }

    #[test]
    fn test_classify_public() {
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            IpClassification::Public
        );
        assert_eq!(
            classify_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            IpClassification::Public
        );
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_ip_classification_display() {
        assert_eq!(format!("{}", IpClassification::Public), "Public");
        assert_eq!(format!("{}", IpClassification::Private), "Private");
        assert_eq!(format!("{}", IpClassification::Loopback), "Loopback");
    }

    // --- DNS Resolution ---

    #[test]
    fn test_resolve_hostname_ip_passthrough() {
        let result = resolve_hostname("127.0.0.1").unwrap();
        assert_eq!(result, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_resolve_hostname_ipv6_passthrough() {
        let result = resolve_hostname("::1").unwrap();
        assert!(result.is_ipv6());
    }

    #[test]
    fn test_resolve_hostname_localhost() {
        let result = resolve_hostname("localhost");
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_hostname_invalid() {
        let result = resolve_hostname("this-does-not-exist-12345.invalid");
        assert!(result.is_err());
    }

    // --- Target Expansion ---

    #[test]
    fn test_expand_target_single_ip() {
        let result = expand_target("192.168.1.1").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_expand_target_cidr() {
        let result = expand_target("10.0.0.0/30").unwrap();
        assert_eq!(result.len(), 2);
    }

    // --- Subnet Helpers ---

    #[test]
    fn test_prefix_to_mask() {
        assert_eq!(prefix_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_mask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_broadcast_address() {
        assert_eq!(
            broadcast_address(Ipv4Addr::new(192, 168, 1, 0), 24),
            Ipv4Addr::new(192, 168, 1, 255)
        );
        assert_eq!(
            broadcast_address(Ipv4Addr::new(10, 0, 0, 0), 8),
            Ipv4Addr::new(10, 255, 255, 255)
        );
    }

    #[test]
    fn test_network_interface_display() {
        let iface = NetworkInterface {
            name: "eth0".to_string(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))],
            is_loopback: false,
        };
        let display = format!("{iface}");
        assert!(display.contains("eth0"));
        assert!(display.contains("192.168.1.100"));
    }
}
