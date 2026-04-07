//! Data Models for Scan Results and Configuration
//!
//! Core data structures shared across the application layers:
//! scanner, persistence, web API, and CLI output.

use std::fmt;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Status of a scanned port.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortStatus {
    /// Port is accepting connections.
    Open,
    /// Port actively refused the connection.
    Closed,
    /// Port did not respond (firewall or network filtering).
    Filtered,
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortStatus::Open => write!(f, "Open"),
            PortStatus::Closed => write!(f, "Closed"),
            PortStatus::Filtered => write!(f, "Filtered"),
        }
    }
}

/// Severity level for a detected vulnerability.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// No risk.
    None,
    /// Informational or low-impact finding.
    Low,
    /// Moderate risk; should be addressed.
    Medium,
    /// Significant risk; prioritize remediation.
    High,
    /// Severe risk; immediate action required.
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::None => write!(f, "None"),
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

impl RiskLevel {
    /// Returns true if this risk level is considered actionable.
    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical
        )
    }

    /// Returns a numeric severity score (0–4) for sorting and comparison.
    pub fn severity_score(&self) -> u8 {
        match self {
            RiskLevel::None => 0,
            RiskLevel::Low => 1,
            RiskLevel::Medium => 2,
            RiskLevel::High => 3,
            RiskLevel::Critical => 4,
        }
    }
}

/// Detailed information about a detected vulnerability on a port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    /// Severity level of the vulnerability.
    pub risk: RiskLevel,
    /// Short name or title of the vulnerability.
    pub name: String,
    /// Detailed description of the vulnerability and its impact.
    pub description: String,
}

impl fmt::Display for VulnerabilityInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} — {}", self.risk, self.name, self.description)
    }
}

/// Result of scanning a single port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    /// The port number that was scanned.
    pub port: u16,
    /// The protocol used for scanning (e.g., "TCP", "UDP", "TCP-SYN").
    pub protocol: String,
    /// The determined status of the port.
    pub status: PortStatus,
    /// Vulnerability information, if any was found for this port.
    pub vulnerability: Option<VulnerabilityInfo>,
}

impl fmt::Display for PortResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Port {}/{}: {}", self.port, self.protocol, self.status)?;
        if let Some(ref vuln) = self.vulnerability {
            write!(f, " [{}]", vuln.name)?;
        }
        Ok(())
    }
}

impl PortResult {
    /// Check if this port has a vulnerability associated.
    pub fn has_vulnerability(&self) -> bool {
        self.vulnerability.is_some()
    }

    /// Get the risk level of the vulnerability, or None if no vulnerability.
    pub fn risk_level(&self) -> RiskLevel {
        self.vulnerability
            .as_ref()
            .map_or(RiskLevel::None, |v| v.risk)
    }

    /// Check if this port is open.
    pub fn is_open(&self) -> bool {
        matches!(self.status, PortStatus::Open)
    }
}

/// Metadata captured during a scan session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Unix timestamp when the scan started.
    pub started_at: u64,
    /// Scan duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Type of scan performed.
    pub scan_type: String,
    /// Port range scanned.
    pub port_range: String,
    /// Timeout per port in milliseconds.
    pub timeout_ms: u64,
    /// Concurrency level used.
    pub concurrency: usize,
    /// Scanner version string.
    pub scanner_version: String,
}

impl Default for ScanMetadata {
    fn default() -> Self {
        Self {
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            duration_ms: None,
            scan_type: "tcp".to_string(),
            port_range: "1-1024".to_string(),
            timeout_ms: 1000,
            concurrency: 500,
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl fmt::Display for ScanMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Scan(type={}, range={}, timeout={}ms, concurrency={})",
            self.scan_type, self.port_range, self.timeout_ms, self.concurrency
        )
    }
}

/// Aggregated results of a complete port scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// The scanned target (IP address or hostname).
    pub target: String,
    /// Individual port results.
    pub ports: Vec<PortResult>,
}

impl ScanResult {
    /// Saves the scan results to the 'scans/' directory in JSON format.
    pub fn save_to_file(&self) -> crate::Result<String> {
        fs::create_dir_all("scans")?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| crate::AppError::Scanner(format!("Time error: {e}")))?
            .as_secs();

        let target_sanitized = self.target.replace(|c: char| !c.is_alphanumeric(), "_");
        let filename = format!("scans/scan_{target_sanitized}_{timestamp}.json");

        let json_str = serde_json::to_string_pretty(self)?;
        fs::write(&filename, json_str)?;

        Ok(filename)
    }

    /// Count open ports.
    pub fn open_count(&self) -> usize {
        self.ports.iter().filter(|p| p.is_open()).count()
    }

    /// Count closed ports.
    pub fn closed_count(&self) -> usize {
        self.ports
            .iter()
            .filter(|p| matches!(p.status, PortStatus::Closed))
            .count()
    }

    /// Count filtered ports.
    pub fn filtered_count(&self) -> usize {
        self.ports
            .iter()
            .filter(|p| matches!(p.status, PortStatus::Filtered))
            .count()
    }

    /// Get only the open ports.
    pub fn open_ports(&self) -> Vec<&PortResult> {
        self.ports.iter().filter(|p| p.is_open()).collect()
    }

    /// Get ports with vulnerabilities.
    pub fn vulnerable_ports(&self) -> Vec<&PortResult> {
        self.ports
            .iter()
            .filter(|p| p.has_vulnerability())
            .collect()
    }

    /// Get the highest risk level found across all ports.
    pub fn max_risk(&self) -> RiskLevel {
        self.ports
            .iter()
            .map(|p| p.risk_level())
            .max()
            .unwrap_or(RiskLevel::None)
    }
}

impl fmt::Display for ScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ScanResult for {}", self.target)?;
        writeln!(
            f,
            "  Total: {} | Open: {} | Closed: {} | Filtered: {}",
            self.ports.len(),
            self.open_count(),
            self.closed_count(),
            self.filtered_count()
        )?;
        write!(f, "  Max Risk: {}", self.max_risk())
    }
}

/// Quick summary of a scan for display in history listings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Target address.
    pub target: String,
    /// Total ports scanned.
    pub total_ports: usize,
    /// Number of open ports.
    pub open_ports: usize,
    /// Highest risk level encountered.
    pub max_risk: RiskLevel,
    /// Unix timestamp of the scan.
    pub timestamp: u64,
    /// Source filename on disk.
    pub filename: String,
}

impl fmt::Display for ScanSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ports scanned, {} open (risk: {})",
            self.target, self.total_ports, self.open_ports, self.max_risk
        )
    }
}

impl From<&ScanResult> for ScanSummary {
    fn from(result: &ScanResult) -> Self {
        Self {
            target: result.target.clone(),
            total_ports: result.ports.len(),
            open_ports: result.open_count(),
            max_risk: result.max_risk(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            filename: String::new(),
        }
    }
}

/// CLI output format selection.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    /// Markdown table output.
    Md,
    /// JSON output.
    Json,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Md => write!(f, "Markdown"),
            OutputFormat::Json => write!(f, "JSON"),
        }
    }
}

/// Type of port scan to perform.
#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum ScanType {
    /// Standard TCP connect scan (no special privileges needed).
    Connect,
    /// TCP SYN (half-open) scan (requires admin/root).
    Syn,
    /// UDP scan.
    Udp,
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanType::Connect => write!(f, "TCP Connect"),
            ScanType::Syn => write!(f, "TCP SYN"),
            ScanType::Udp => write!(f, "UDP"),
        }
    }
}

impl ScanType {
    /// Get the protocol string used in results.
    pub fn protocol_str(&self) -> &'static str {
        match self {
            ScanType::Connect => "TCP",
            ScanType::Syn => "TCP-SYN",
            ScanType::Udp => "UDP",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- PortStatus ---

    #[test]
    fn test_port_status_display() {
        assert_eq!(format!("{}", PortStatus::Open), "Open");
        assert_eq!(format!("{}", PortStatus::Closed), "Closed");
        assert_eq!(format!("{}", PortStatus::Filtered), "Filtered");
    }

    #[test]
    fn test_port_status_serialization() {
        let json = serde_json::to_string(&PortStatus::Open).unwrap();
        assert_eq!(json, "\"Open\"");
    }

    // --- RiskLevel ---

    #[test]
    fn test_risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::Critical), "Critical");
        assert_eq!(format!("{}", RiskLevel::None), "None");
    }

    #[test]
    fn test_risk_level_is_actionable() {
        assert!(!RiskLevel::None.is_actionable());
        assert!(!RiskLevel::Low.is_actionable());
        assert!(RiskLevel::Medium.is_actionable());
        assert!(RiskLevel::High.is_actionable());
        assert!(RiskLevel::Critical.is_actionable());
    }

    #[test]
    fn test_risk_level_severity_score() {
        assert_eq!(RiskLevel::None.severity_score(), 0);
        assert_eq!(RiskLevel::Critical.severity_score(), 4);
        assert!(RiskLevel::Critical.severity_score() > RiskLevel::High.severity_score());
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
        assert!(RiskLevel::Low > RiskLevel::None);
    }

    #[test]
    fn test_risk_level_serialization() {
        let json = serde_json::to_string(&RiskLevel::Critical).unwrap();
        assert_eq!(json, "\"Critical\"");
    }

    // --- VulnerabilityInfo ---

    #[test]
    fn test_vulnerability_info_display() {
        let vuln = VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "Test Vuln".to_string(),
            description: "A test vulnerability".to_string(),
        };
        let display = format!("{vuln}");
        assert!(display.contains("High"));
        assert!(display.contains("Test Vuln"));
    }

    // --- PortResult ---

    #[test]
    fn test_port_result_display() {
        let result = PortResult {
            port: 80,
            protocol: "TCP".to_string(),
            status: PortStatus::Open,
            vulnerability: None,
        };
        let display = format!("{result}");
        assert!(display.contains("80"));
        assert!(display.contains("TCP"));
        assert!(display.contains("Open"));
    }

    #[test]
    fn test_port_result_is_open() {
        let open = PortResult {
            port: 80,
            protocol: "TCP".to_string(),
            status: PortStatus::Open,
            vulnerability: None,
        };
        let closed = PortResult {
            port: 81,
            protocol: "TCP".to_string(),
            status: PortStatus::Closed,
            vulnerability: None,
        };
        assert!(open.is_open());
        assert!(!closed.is_open());
    }

    #[test]
    fn test_port_result_has_vulnerability() {
        let no_vuln = PortResult {
            port: 80,
            protocol: "TCP".to_string(),
            status: PortStatus::Open,
            vulnerability: None,
        };
        let with_vuln = PortResult {
            port: 23,
            protocol: "TCP".to_string(),
            status: PortStatus::Open,
            vulnerability: Some(VulnerabilityInfo {
                risk: RiskLevel::Critical,
                name: "Telnet".to_string(),
                description: "Insecure".to_string(),
            }),
        };
        assert!(!no_vuln.has_vulnerability());
        assert!(with_vuln.has_vulnerability());
    }

    #[test]
    fn test_port_result_risk_level() {
        let result = PortResult {
            port: 23,
            protocol: "TCP".to_string(),
            status: PortStatus::Open,
            vulnerability: Some(VulnerabilityInfo {
                risk: RiskLevel::Critical,
                name: "Telnet".to_string(),
                description: "Insecure".to_string(),
            }),
        };
        assert_eq!(result.risk_level(), RiskLevel::Critical);
    }

    // --- ScanResult ---

    #[test]
    fn test_scan_result_counts() {
        let result = ScanResult {
            target: "localhost".to_string(),
            ports: vec![
                PortResult {
                    port: 80,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Open,
                    vulnerability: None,
                },
                PortResult {
                    port: 81,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Closed,
                    vulnerability: None,
                },
                PortResult {
                    port: 82,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Filtered,
                    vulnerability: None,
                },
            ],
        };
        assert_eq!(result.open_count(), 1);
        assert_eq!(result.closed_count(), 1);
        assert_eq!(result.filtered_count(), 1);
    }

    #[test]
    fn test_scan_result_open_ports() {
        let result = ScanResult {
            target: "localhost".to_string(),
            ports: vec![
                PortResult {
                    port: 80,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Open,
                    vulnerability: None,
                },
                PortResult {
                    port: 81,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Closed,
                    vulnerability: None,
                },
            ],
        };
        assert_eq!(result.open_ports().len(), 1);
        assert_eq!(result.open_ports()[0].port, 80);
    }

    #[test]
    fn test_scan_result_max_risk() {
        let result = ScanResult {
            target: "localhost".to_string(),
            ports: vec![
                PortResult {
                    port: 80,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Open,
                    vulnerability: Some(VulnerabilityInfo {
                        risk: RiskLevel::Low,
                        name: "HTTP".to_string(),
                        description: "".to_string(),
                    }),
                },
                PortResult {
                    port: 23,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Open,
                    vulnerability: Some(VulnerabilityInfo {
                        risk: RiskLevel::Critical,
                        name: "Telnet".to_string(),
                        description: "".to_string(),
                    }),
                },
            ],
        };
        assert_eq!(result.max_risk(), RiskLevel::Critical);
    }

    #[test]
    fn test_scan_result_display() {
        let result = ScanResult {
            target: "127.0.0.1".to_string(),
            ports: vec![PortResult {
                port: 80,
                protocol: "TCP".to_string(),
                status: PortStatus::Open,
                vulnerability: None,
            }],
        };
        let display = format!("{result}");
        assert!(display.contains("127.0.0.1"));
        assert!(display.contains("Open: 1"));
    }

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            target: "127.0.0.1".to_string(),
            ports: vec![PortResult {
                port: 80,
                protocol: "TCP".to_string(),
                status: PortStatus::Open,
                vulnerability: None,
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"port\":80"));
        assert!(json.contains("\"status\":\"Open\""));
    }

    // --- ScanSummary ---

    #[test]
    fn test_scan_summary_from_result() {
        let result = ScanResult {
            target: "test".to_string(),
            ports: vec![
                PortResult {
                    port: 80,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Open,
                    vulnerability: None,
                },
                PortResult {
                    port: 81,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Closed,
                    vulnerability: None,
                },
            ],
        };
        let summary = ScanSummary::from(&result);
        assert_eq!(summary.target, "test");
        assert_eq!(summary.total_ports, 2);
        assert_eq!(summary.open_ports, 1);
    }

    #[test]
    fn test_scan_summary_display() {
        let summary = ScanSummary {
            target: "localhost".to_string(),
            total_ports: 100,
            open_ports: 5,
            max_risk: RiskLevel::High,
            timestamp: 0,
            filename: String::new(),
        };
        let display = format!("{summary}");
        assert!(display.contains("localhost"));
        assert!(display.contains("5 open"));
    }

    // --- ScanMetadata ---

    #[test]
    fn test_scan_metadata_default() {
        let meta = ScanMetadata::default();
        assert!(meta.started_at > 0);
        assert_eq!(meta.scan_type, "tcp");
    }

    #[test]
    fn test_scan_metadata_display() {
        let display = format!("{}", ScanMetadata::default());
        assert!(display.contains("tcp"));
    }

    // --- OutputFormat ---

    #[test]
    fn test_output_format_display() {
        assert_eq!(format!("{}", OutputFormat::Md), "Markdown");
        assert_eq!(format!("{}", OutputFormat::Json), "JSON");
    }

    // --- ScanType ---

    #[test]
    fn test_scan_type_display() {
        assert_eq!(format!("{}", ScanType::Connect), "TCP Connect");
        assert_eq!(format!("{}", ScanType::Syn), "TCP SYN");
        assert_eq!(format!("{}", ScanType::Udp), "UDP");
    }

    #[test]
    fn test_scan_type_protocol_str() {
        assert_eq!(ScanType::Connect.protocol_str(), "TCP");
        assert_eq!(ScanType::Syn.protocol_str(), "TCP-SYN");
        assert_eq!(ScanType::Udp.protocol_str(), "UDP");
    }
}
