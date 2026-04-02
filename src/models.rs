use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub status: PortStatus,
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
