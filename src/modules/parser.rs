//! Port Range & Target Parser Module
//!
//! Centralized parsing and validation for port ranges and target specifications.
//! Extracted from main.rs for better modularity and testability.

use std::fmt;
use std::net::{IpAddr, ToSocketAddrs};

use serde::{Deserialize, Serialize};

/// Validated port range specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    /// The raw input string that produced this range.
    pub raw: String,
    /// Start port (inclusive).
    pub start: u16,
    /// End port (inclusive).
    pub end: u16,
}

impl PortRange {
    /// Create a new port range.
    pub fn new(start: u16, end: u16) -> Self {
        Self {
            raw: format!("{start}-{end}"),
            start,
            end,
        }
    }

    /// Number of ports in this range.
    pub fn count(&self) -> usize {
        (self.end as usize) - (self.start as usize) + 1
    }

    /// Check if a port is within this range.
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    /// Convert to a vector of port numbers.
    pub fn to_vec(&self) -> Vec<u16> {
        (self.start..=self.end).collect()
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// A parsed, validated target specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSpecification {
    /// The original raw input string.
    pub raw: String,
    /// Resolved IP address.
    pub ip: IpAddr,
    /// Whether this target is a hostname (vs. direct IP).
    pub is_hostname: bool,
}

impl fmt::Display for TargetSpecification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_hostname {
            write!(f, "{} ({})", self.raw, self.ip)
        } else {
            write!(f, "{}", self.ip)
        }
    }
}

/// Parse a port range string into a vector of individual port numbers.
///
/// Supports the following formats:
/// - Single port: `"80"`
/// - Range: `"1-1024"`
/// - Comma-separated: `"80,443,8080"`
/// - Mixed: `"22,80,443,1000-2000"`
///
/// Invalid ports (outside 1–65535) are silently skipped. Duplicates are removed
/// and the result is sorted in ascending order.
pub fn parse_ports(range_str: &str) -> Vec<u16> {
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
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Parse a port range string into a vector of [`PortRange`] structs.
///
/// Unlike [`parse_ports`], this preserves the range structure.
pub fn parse_port_ranges(range_str: &str) -> Vec<PortRange> {
    let mut ranges = Vec::new();
    for part in range_str.split(',') {
        let part_str = part.trim();
        if part_str.is_empty() {
            continue;
        }

        let sub_parts: Vec<&str> = part_str.split('-').collect();
        if sub_parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (sub_parts[0].parse::<u16>(), sub_parts[1].parse::<u16>())
            {
                if start >= 1 && end >= 1 {
                    ranges.push(PortRange {
                        raw: part_str.to_string(),
                        start: start.min(end),
                        end: start.max(end),
                    });
                }
            }
        } else if sub_parts.len() == 1 {
            if let Ok(p) = sub_parts[0].parse::<u16>() {
                if p >= 1 {
                    ranges.push(PortRange {
                        raw: part_str.to_string(),
                        start: p,
                        end: p,
                    });
                }
            }
        }
    }
    ranges
}

/// Validate a port range input string.
///
/// Returns `Ok(())` if valid, or `Err` with a descriptive message.
pub fn validate_port_input(input: &str) -> Result<(), String> {
    if input.trim().is_empty() {
        return Err("Port range cannot be empty".to_string());
    }

    for part in input.split(',') {
        let part_str = part.trim();
        if part_str.is_empty() {
            continue;
        }

        let sub_parts: Vec<&str> = part_str.split('-').collect();
        match sub_parts.len() {
            1 => {
                let p: u32 = sub_parts[0]
                    .parse()
                    .map_err(|_| format!("Invalid port number: '{}'", sub_parts[0]))?;
                if !(1..=65535).contains(&p) {
                    return Err(format!("Port {p} out of valid range (1-65535)"));
                }
            }
            2 => {
                let start: u32 = sub_parts[0]
                    .parse()
                    .map_err(|_| format!("Invalid start port: '{}'", sub_parts[0]))?;
                let end: u32 = sub_parts[1]
                    .parse()
                    .map_err(|_| format!("Invalid end port: '{}'", sub_parts[1]))?;
                if !(1..=65535).contains(&start) {
                    return Err(format!("Start port {start} out of range (1-65535)"));
                }
                if !(1..=65535).contains(&end) {
                    return Err(format!("End port {end} out of range (1-65535)"));
                }
                if start > end {
                    return Err(format!("Start port ({start}) exceeds end port ({end})"));
                }
            }
            _ => {
                return Err(format!("Invalid port range format: '{part_str}'"));
            }
        }
    }
    Ok(())
}

/// Estimate the total number of ports from a range string without allocating.
pub fn estimate_port_count(range_str: &str) -> usize {
    let mut count = 0;
    for part in range_str.split(',') {
        let part_str = part.trim();
        if part_str.is_empty() {
            continue;
        }
        let sub_parts: Vec<&str> = part_str.split('-').collect();
        if sub_parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (sub_parts[0].parse::<u32>(), sub_parts[1].parse::<u32>())
            {
                count += (end.max(start) - end.min(start) + 1) as usize;
            }
        } else {
            count += 1;
        }
    }
    count.max(1)
}

/// Resolve a target string (IP or hostname) to an IP address.
///
/// # Errors
///
/// Returns an error if the target cannot be resolved.
pub fn resolve_target(target: &str) -> crate::Result<IpAddr> {
    // Direct IP parse
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    // DNS resolution via ToSocketAddrs
    let probe = format!("{target}:80");
    if let Ok(mut addrs) = probe.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(addr.ip());
        }
    }
    Err(crate::AppError::Resolution(target.to_string()))
}

/// Parse and resolve a target into a [`TargetSpecification`].
pub fn parse_target(target: &str) -> crate::Result<TargetSpecification> {
    let is_hostname = target.parse::<IpAddr>().is_err();
    let ip = resolve_target(target)?;
    Ok(TargetSpecification {
        raw: target.to_string(),
        ip,
        is_hostname,
    })
}

/// Well-known port presets for quick scanning profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPreset {
    /// Top 100 ports (1-100)
    Top100,
    /// Standard range (1-1024)
    Standard,
    /// Full scan (1-65535)
    Full,
    /// Web ports only
    WebPorts,
    /// Commonly vulnerable ports
    CommonVulnerable,
}

impl ScanPreset {
    /// Get the port range string for this preset.
    pub fn range_str(&self) -> &'static str {
        match self {
            ScanPreset::Top100 => "1-100",
            ScanPreset::Standard => "1-1024",
            ScanPreset::Full => "1-65535",
            ScanPreset::WebPorts => "80,443,8080,8443",
            ScanPreset::CommonVulnerable => {
                "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
            }
        }
    }

    /// Get a human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            ScanPreset::Top100 => "Top 100 Ports",
            ScanPreset::Standard => "Standard (1-1024)",
            ScanPreset::Full => "Full Scan (1-65535)",
            ScanPreset::WebPorts => "Web Ports",
            ScanPreset::CommonVulnerable => "Common Vulnerable Ports",
        }
    }
}

impl fmt::Display for ScanPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.description(), self.range_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_ports ---

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
    fn test_parse_ports_overlap_dedup() {
        let ports = parse_ports("80,70-85,22");
        assert!(ports.contains(&22));
        assert!(ports.contains(&80));
        // No duplicates
        let unique_count = ports.len();
        let mut deduped = ports.clone();
        deduped.dedup();
        assert_eq!(unique_count, deduped.len());
    }

    #[test]
    fn test_parse_ports_invalid_skipped() {
        assert_eq!(parse_ports("abc, 70000, -1"), Vec::<u16>::new());
    }

    #[test]
    fn test_parse_ports_empty() {
        assert_eq!(parse_ports(""), Vec::<u16>::new());
    }

    // --- parse_port_ranges ---

    #[test]
    fn test_parse_port_ranges_single() {
        let ranges = parse_port_ranges("80");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 80);
        assert_eq!(ranges[0].end, 80);
    }

    #[test]
    fn test_parse_port_ranges_range() {
        let ranges = parse_port_ranges("1-1024");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 1);
        assert_eq!(ranges[0].end, 1024);
    }

    #[test]
    fn test_parse_port_ranges_mixed() {
        let ranges = parse_port_ranges("22,80,1000-2000");
        assert_eq!(ranges.len(), 3);
    }

    // --- PortRange ---

    #[test]
    fn test_port_range_count() {
        let r = PortRange::new(1, 100);
        assert_eq!(r.count(), 100);
    }

    #[test]
    fn test_port_range_contains() {
        let r = PortRange::new(80, 443);
        assert!(r.contains(80));
        assert!(r.contains(200));
        assert!(r.contains(443));
        assert!(!r.contains(79));
        assert!(!r.contains(444));
    }

    #[test]
    fn test_port_range_to_vec() {
        let r = PortRange::new(1, 3);
        assert_eq!(r.to_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn test_port_range_display() {
        assert_eq!(format!("{}", PortRange::new(80, 80)), "80");
        assert_eq!(format!("{}", PortRange::new(1, 1024)), "1-1024");
    }

    // --- validate_port_input ---

    #[test]
    fn test_validate_valid_inputs() {
        assert!(validate_port_input("80").is_ok());
        assert!(validate_port_input("1-1024").is_ok());
        assert!(validate_port_input("22,80,443").is_ok());
        assert!(validate_port_input("22,80,1000-2000").is_ok());
    }

    #[test]
    fn test_validate_invalid_inputs() {
        assert!(validate_port_input("").is_err());
        assert!(validate_port_input("0").is_err());
        assert!(validate_port_input("70000").is_err());
        assert!(validate_port_input("abc").is_err());
        assert!(validate_port_input("100-50").is_err());
    }

    // --- estimate_port_count ---

    #[test]
    fn test_estimate_port_count() {
        assert_eq!(estimate_port_count("1-1024"), 1024);
        assert_eq!(estimate_port_count("80"), 1);
        assert_eq!(estimate_port_count("80,443"), 2);
        assert_eq!(estimate_port_count("1-100,200-300"), 201);
    }

    // --- resolve_target ---

    #[test]
    fn test_resolve_target_ip() {
        assert!(resolve_target("127.0.0.1").is_ok());
        assert!(resolve_target("::1").is_ok());
    }

    #[test]
    fn test_resolve_target_localhost() {
        assert!(resolve_target("localhost").is_ok());
    }

    #[test]
    fn test_resolve_target_invalid() {
        assert!(resolve_target("nonexistent-host-12345.invalid").is_err());
    }

    // --- parse_target ---

    #[test]
    fn test_parse_target_ip() {
        let spec = parse_target("127.0.0.1").unwrap();
        assert!(!spec.is_hostname);
        assert_eq!(spec.raw, "127.0.0.1");
    }

    #[test]
    fn test_parse_target_hostname() {
        let spec = parse_target("localhost").unwrap();
        assert!(spec.is_hostname);
    }

    #[test]
    fn test_target_specification_display() {
        let spec = TargetSpecification {
            raw: "localhost".to_string(),
            ip: "127.0.0.1".parse().unwrap(),
            is_hostname: true,
        };
        let display = format!("{spec}");
        assert!(display.contains("localhost"));
        assert!(display.contains("127.0.0.1"));
    }

    // --- ScanPreset ---

    #[test]
    fn test_scan_presets() {
        assert_eq!(ScanPreset::Top100.range_str(), "1-100");
        assert_eq!(ScanPreset::Standard.range_str(), "1-1024");
        assert!(ScanPreset::Full.range_str().contains("65535"));
    }

    #[test]
    fn test_scan_preset_display() {
        let display = format!("{}", ScanPreset::Standard);
        assert!(display.contains("1-1024"));
    }
}
