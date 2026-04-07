//! Application Configuration Module
//!
//! Centralizes all configurable parameters for the scanner, web server,
//! and output formatting. Supports loading from environment variables
//! and provides sensible defaults.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Top-level application configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// Scan-specific configuration.
    pub scan: ScanConfig,
    /// Web server configuration.
    pub server: ServerConfig,
    /// Output formatting configuration.
    pub output: OutputConfig,
}

impl AppConfig {
    /// Load configuration from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        Self {
            scan: ScanConfig::from_env(),
            server: ServerConfig::from_env(),
            output: OutputConfig::default(),
        }
    }

    /// Validate the entire configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if let Err(e) = self.scan.validate() {
            errors.extend(e);
        }
        if let Err(e) = self.server.validate() {
            errors.extend(e);
        }
        if let Err(e) = self.output.validate() {
            errors.extend(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl fmt::Display for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Application Configuration:")?;
        writeln!(f, "  {}", self.scan)?;
        writeln!(f, "  {}", self.server)?;
        write!(f, "  {}", self.output)
    }
}

/// Scan engine configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Default timeout per port in milliseconds.
    pub default_timeout_ms: u64,
    /// Default concurrency limit for TCP connect scans.
    pub default_concurrency: usize,
    /// Maximum allowed concurrency for TCP connect scans.
    pub max_concurrency_tcp: usize,
    /// Maximum allowed concurrency for TCP SYN scans.
    pub max_concurrency_syn: usize,
    /// Maximum allowed concurrency for UDP scans.
    pub max_concurrency_udp: usize,
    /// Default port range when none is specified.
    pub default_port_range: String,
    /// Whether to enable banner grabbing by default.
    pub banner_grab_enabled: bool,
    /// Timeout for banner grabbing in milliseconds.
    pub banner_grab_timeout_ms: u64,
    /// Maximum number of ports that can be scanned in a single request.
    pub max_port_count: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 1000,
            default_concurrency: 500,
            max_concurrency_tcp: 2000,
            max_concurrency_syn: 200,
            max_concurrency_udp: 500,
            default_port_range: "1-1024".to_string(),
            banner_grab_enabled: false,
            banner_grab_timeout_ms: 3000,
            max_port_count: 65535,
        }
    }
}

impl ScanConfig {
    /// Load scan configuration from environment variables.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("SCAN_TIMEOUT") {
            if let Ok(v) = val.parse() {
                config.default_timeout_ms = v;
            }
        }
        if let Ok(val) = std::env::var("SCAN_CONCURRENCY") {
            if let Ok(v) = val.parse() {
                config.default_concurrency = v;
            }
        }
        if let Ok(val) = std::env::var("SCAN_MAX_TCP") {
            if let Ok(v) = val.parse() {
                config.max_concurrency_tcp = v;
            }
        }
        if let Ok(val) = std::env::var("SCAN_MAX_SYN") {
            if let Ok(v) = val.parse() {
                config.max_concurrency_syn = v;
            }
        }
        if let Ok(val) = std::env::var("SCAN_MAX_UDP") {
            if let Ok(v) = val.parse() {
                config.max_concurrency_udp = v;
            }
        }
        if let Ok(val) = std::env::var("SCAN_DEFAULT_RANGE") {
            config.default_port_range = val;
        }
        if let Ok(val) = std::env::var("SCAN_BANNER_GRAB") {
            config.banner_grab_enabled = val == "1" || val.to_lowercase() == "true";
        }

        config
    }

    /// Validate scan configuration parameters.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.default_timeout_ms == 0 {
            errors.push("Scan timeout must be greater than 0".to_string());
        }
        if self.default_timeout_ms > 60000 {
            errors.push("Scan timeout should not exceed 60000ms".to_string());
        }
        if self.default_concurrency == 0 {
            errors.push("Default concurrency must be at least 1".to_string());
        }
        if self.max_concurrency_tcp == 0 {
            errors.push("Max TCP concurrency must be at least 1".to_string());
        }
        if self.max_concurrency_syn == 0 {
            errors.push("Max SYN concurrency must be at least 1".to_string());
        }
        if self.max_concurrency_udp == 0 {
            errors.push("Max UDP concurrency must be at least 1".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Get the effective concurrency cap for a given scan type.
    pub fn effective_concurrency(&self, scan_type: &str, requested: usize) -> usize {
        let cap = match scan_type {
            "syn" => self.max_concurrency_syn,
            "udp" => self.max_concurrency_udp,
            _ => self.max_concurrency_tcp,
        };
        requested.min(cap).max(1)
    }
}

impl fmt::Display for ScanConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScanConfig(timeout={}ms, concurrency={}, range={})",
            self.default_timeout_ms, self.default_concurrency, self.default_port_range
        )
    }
}

/// Web server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Port to listen on.
    pub port: u16,
    /// Bind address.
    pub bind_address: String,
    /// Whether CORS is enabled.
    pub cors_enabled: bool,
    /// Maximum request body size in bytes.
    pub max_body_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 3000,
            bind_address: "127.0.0.1".to_string(),
            cors_enabled: true,
            max_body_size: 1_048_576, // 1MB
        }
    }
}

impl ServerConfig {
    /// Load server configuration from environment variables.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("PORT") {
            if let Ok(v) = val.parse() {
                config.port = v;
            }
        }
        if let Ok(val) = std::env::var("BIND_ADDRESS") {
            config.bind_address = val;
        }
        if let Ok(val) = std::env::var("CORS_ENABLED") {
            config.cors_enabled = val != "0" && val.to_lowercase() != "false";
        }

        config
    }

    /// Validate server configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.port == 0 {
            errors.push("Server port must be greater than 0".to_string());
        }
        if self.bind_address.is_empty() {
            errors.push("Bind address cannot be empty".to_string());
        }
        if self.max_body_size == 0 {
            errors.push("Max body size must be greater than 0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Get the full socket address string.
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.bind_address, self.port)
    }
}

impl fmt::Display for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServerConfig({}:{}, cors={})",
            self.bind_address, self.port, self.cors_enabled
        )
    }
}

/// Output formatting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Whether to show only open ports in CLI output.
    pub open_only: bool,
    /// Whether to include vulnerability details in output.
    pub show_vulnerabilities: bool,
    /// Whether to colorize terminal output.
    pub colorize: bool,
    /// Maximum number of results to show in CLI.
    pub max_display_results: usize,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            open_only: false,
            show_vulnerabilities: true,
            colorize: true,
            max_display_results: 10000,
        }
    }
}

impl OutputConfig {
    /// Validate output configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.max_display_results == 0 {
            errors.push("Max display results must be at least 1".to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl fmt::Display for OutputConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OutputConfig(open_only={}, vulns={}, color={})",
            self.open_only, self.show_vulnerabilities, self.colorize
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- AppConfig ---

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert_eq!(config.scan.default_timeout_ms, 1000);
        assert_eq!(config.server.port, 3000);
    }

    #[test]
    fn test_app_config_validate_default() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_app_config_display() {
        let config = AppConfig::default();
        let display = format!("{config}");
        assert!(display.contains("Application Configuration"));
    }

    // --- ScanConfig ---

    #[test]
    fn test_scan_config_default() {
        let config = ScanConfig::default();
        assert_eq!(config.default_timeout_ms, 1000);
        assert_eq!(config.default_concurrency, 500);
        assert_eq!(config.max_concurrency_tcp, 2000);
        assert_eq!(config.max_concurrency_syn, 200);
        assert_eq!(config.max_concurrency_udp, 500);
    }

    #[test]
    fn test_scan_config_validate() {
        let config = ScanConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_scan_config_validate_bad_timeout() {
        let mut config = ScanConfig::default();
        config.default_timeout_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_scan_config_effective_concurrency() {
        let config = ScanConfig::default();
        assert_eq!(config.effective_concurrency("tcp", 5000), 2000);
        assert_eq!(config.effective_concurrency("syn", 500), 200);
        assert_eq!(config.effective_concurrency("udp", 100), 100);
        assert_eq!(config.effective_concurrency("tcp", 0), 1);
    }

    #[test]
    fn test_scan_config_display() {
        let config = ScanConfig::default();
        let display = format!("{config}");
        assert!(display.contains("1000ms"));
    }

    // --- ServerConfig ---

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.port, 3000);
        assert_eq!(config.bind_address, "127.0.0.1");
        assert!(config.cors_enabled);
    }

    #[test]
    fn test_server_config_validate() {
        assert!(ServerConfig::default().validate().is_ok());
    }

    #[test]
    fn test_server_config_validate_bad_port() {
        let mut config = ServerConfig::default();
        config.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_server_config_socket_addr() {
        let config = ServerConfig::default();
        assert_eq!(config.socket_addr(), "127.0.0.1:3000");
    }

    #[test]
    fn test_server_config_display() {
        let display = format!("{}", ServerConfig::default());
        assert!(display.contains("3000"));
    }

    // --- OutputConfig ---

    #[test]
    fn test_output_config_default() {
        let config = OutputConfig::default();
        assert!(!config.open_only);
        assert!(config.show_vulnerabilities);
        assert!(config.colorize);
    }

    #[test]
    fn test_output_config_validate() {
        assert!(OutputConfig::default().validate().is_ok());
    }

    #[test]
    fn test_output_config_validate_bad() {
        let mut config = OutputConfig::default();
        config.max_display_results = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_output_config_display() {
        let display = format!("{}", OutputConfig::default());
        assert!(display.contains("OutputConfig"));
    }
}
