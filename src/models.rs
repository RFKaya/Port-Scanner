use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub risk: RiskLevel,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub status: PortStatus,
    pub vulnerability: Option<VulnerabilityInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub ports: Vec<PortResult>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Md,
    Json,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum ScanType {
    Connect,
    Syn,
    Udp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_port_status_serialization() {
        let status = PortStatus::Open;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"Open\"");
    }

    #[test]
    fn test_risk_level_serialization() {
        let risk = RiskLevel::Critical;
        let json = serde_json::to_string(&risk).unwrap();
        assert_eq!(json, "\"Critical\"");
    }

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            target: "127.0.0.1".to_string(),
            ports: vec![
                PortResult {
                    port: 80,
                    protocol: "TCP".to_string(),
                    status: PortStatus::Open,
                    vulnerability: None,
                }
            ],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"port\":80"));
        assert!(json.contains("\"status\":\"Open\""));
    }
}
