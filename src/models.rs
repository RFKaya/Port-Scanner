use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

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

impl ScanResult {
    /// Saves the scan results to the 'scans/' directory in JSON format.
    pub fn save_to_file(&self) -> crate::Result<String> {
        // Ensure the directory exists
        fs::create_dir_all("scans")?;

        // Create a unique filename (target_name + timestamp)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| crate::AppError::Scanner(format!("Time error: {e}")))?
            .as_secs();

        // Sanitize target name for filename (replace non-alphanumeric with _)
        let target_sanitized = self.target.replace(|c: char| !c.is_alphanumeric(), "_");
        let filename = format!("scans/scan_{target_sanitized}_{timestamp}.json");

        // Save the scan as pretty-printed JSON to disk
        let json_str = serde_json::to_string_pretty(self)?;
        fs::write(&filename, json_str)?;

        Ok(filename)
    }
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
}
