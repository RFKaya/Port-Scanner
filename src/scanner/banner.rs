//! Service Banner Grabbing Module
//!
//! Connects to open ports and attempts to read the service identification banner.
//! Supports protocol-specific probes for HTTP, SMTP, FTP, SSH, and other services.
//! This is used to identify the running service and its version after a port is
//! found to be open by the scanner.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Maximum number of bytes to read from a banner response.
const MAX_BANNER_LENGTH: usize = 1024;

/// Default timeout for banner grabbing operations.
const DEFAULT_BANNER_TIMEOUT_MS: u64 = 3000;

/// Result of a banner grab attempt on a single port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerResult {
    /// The port that was probed.
    pub port: u16,
    /// Raw banner string received from the service (if any).
    pub raw_banner: Option<String>,
    /// Identified service name derived from the banner.
    pub service_name: Option<String>,
    /// Identified service version derived from the banner.
    pub service_version: Option<String>,
    /// Which probe type was used to elicit the response.
    pub probe_used: ProbeType,
}

impl fmt::Display for BannerResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let service = self.service_name.as_deref().unwrap_or("Unknown");
        let version = self.service_version.as_deref().unwrap_or("");
        let banner_preview = self
            .raw_banner
            .as_deref()
            .unwrap_or("")
            .chars()
            .take(60)
            .collect::<String>();

        write!(
            f,
            "Port {}: {} {} | Banner: {}",
            self.port, service, version, banner_preview
        )
    }
}

/// Types of protocol probes that can be sent to elicit a banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeType {
    /// No probe sent; just read whatever the service sends on connect.
    Passive,
    /// Send an HTTP GET request to identify web servers.
    HttpGet,
    /// Send an SMTP EHLO command.
    SmtpEhlo,
    /// Send an FTP NOOP after the welcome banner.
    FtpNoop,
    /// Send a generic probe string to coax a response.
    GenericProbe,
}

impl fmt::Display for ProbeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeType::Passive => write!(f, "Passive"),
            ProbeType::HttpGet => write!(f, "HTTP-GET"),
            ProbeType::SmtpEhlo => write!(f, "SMTP-EHLO"),
            ProbeType::FtpNoop => write!(f, "FTP-NOOP"),
            ProbeType::GenericProbe => write!(f, "Generic"),
        }
    }
}

/// Defines protocol-specific probe payloads sent to services.
struct ServiceProbe {
    probe_type: ProbeType,
    payload: &'static [u8],
}

/// Returns the appropriate probe for a given port number.
/// Well-known ports get protocol-specific probes; others get a passive read.
fn get_probe_for_port(port: u16) -> ServiceProbe {
    match port {
        80 | 8080 | 8000 | 8443 | 443 | 3000 | 8081 | 8888 => ServiceProbe {
            probe_type: ProbeType::HttpGet,
            payload: b"GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: SecOps-Scanner/1.7\r\n\r\n",
        },
        25 | 465 | 587 => ServiceProbe {
            probe_type: ProbeType::SmtpEhlo,
            payload: b"EHLO scanner.local\r\n",
        },
        21 | 990 => ServiceProbe {
            probe_type: ProbeType::FtpNoop,
            payload: b"", // FTP servers send banner on connect; read passively first
        },
        22 | 2222 => ServiceProbe {
            probe_type: ProbeType::Passive,
            payload: b"", // SSH sends identification string on connect
        },
        _ => ServiceProbe {
            probe_type: ProbeType::GenericProbe,
            payload: b"\r\n",
        },
    }
}

/// Grab the service banner from an open port.
///
/// Connects to the target address, optionally sends a protocol-specific probe,
/// and reads the response. The raw response is then analyzed to identify the
/// service and version.
///
/// # Arguments
///
/// * `target` - Target IP address.
/// * `port` - Target port number (must already be confirmed as open).
/// * `timeout_ms` - Maximum time to wait for a response, in milliseconds.
///   If `None`, uses [`DEFAULT_BANNER_TIMEOUT_MS`].
///
/// # Returns
///
/// A [`BannerResult`] containing the raw banner and any identified service info.
pub async fn grab_banner(target: IpAddr, port: u16, timeout_ms: Option<u64>) -> BannerResult {
    let timeout_dur = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_BANNER_TIMEOUT_MS));
    let probe = get_probe_for_port(port);
    let socket_addr = std::net::SocketAddr::new(target, port);

    // Attempt to connect with timeout
    let stream_result = timeout(timeout_dur, TcpStream::connect(&socket_addr)).await;

    let mut stream = match stream_result {
        Ok(Ok(s)) => s,
        _ => {
            return BannerResult {
                port,
                raw_banner: None,
                service_name: None,
                service_version: None,
                probe_used: probe.probe_type,
            };
        }
    };

    // For passive probes and FTP, first try to read the initial banner
    let mut banner_buf = vec![0u8; MAX_BANNER_LENGTH];
    let mut raw_banner = String::new();

    if probe.probe_type == ProbeType::Passive
        || probe.probe_type == ProbeType::FtpNoop
        || probe.probe_type == ProbeType::GenericProbe
    {
        // Read with a short timeout for the initial banner
        let read_timeout = Duration::from_millis(1500);
        if let Ok(Ok(n)) = timeout(read_timeout, stream.read(&mut banner_buf)).await {
            if n > 0 {
                raw_banner = sanitize_banner(&banner_buf[..n]);
            }
        }
    }

    // If we have a payload to send (and haven't already gotten a banner), send it
    if !probe.payload.is_empty() && raw_banner.is_empty() {
        let _ = stream.write_all(probe.payload).await;

        // Read response
        let read_timeout = Duration::from_millis(2000);
        if let Ok(Ok(n)) = timeout(read_timeout, stream.read(&mut banner_buf)).await {
            if n > 0 {
                raw_banner = sanitize_banner(&banner_buf[..n]);
            }
        }
    }

    // Gracefully shutdown the connection
    let _ = stream.shutdown().await;

    // Identify service from banner
    let (service_name, service_version) = identify_service(&raw_banner, port);

    BannerResult {
        port,
        raw_banner: if raw_banner.is_empty() {
            None
        } else {
            Some(raw_banner)
        },
        service_name,
        service_version,
        probe_used: probe.probe_type,
    }
}

/// Remove non-printable characters and trim the banner to a reasonable length.
fn sanitize_banner(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    raw.chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .take(MAX_BANNER_LENGTH)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Analyze a raw banner string to identify the service and version.
///
/// Uses pattern matching against known service signature strings.
fn identify_service(banner: &str, port: u16) -> (Option<String>, Option<String>) {
    if banner.is_empty() {
        return (None, None);
    }

    let lower = banner.to_lowercase();

    // --- SSH ---
    if lower.starts_with("ssh-") {
        let version = extract_version_after(banner, "SSH-");
        return (Some("SSH".to_string()), version);
    }

    // --- HTTP / Web Servers ---
    if lower.contains("http/") {
        let service = if lower.contains("nginx") {
            "Nginx"
        } else if lower.contains("apache") {
            "Apache"
        } else if lower.contains("iis") {
            "Microsoft IIS"
        } else if lower.contains("lighttpd") {
            "Lighttpd"
        } else if lower.contains("caddy") {
            "Caddy"
        } else {
            "HTTP Server"
        };

        let version = extract_server_version(banner);
        return (Some(service.to_string()), version);
    }

    // --- FTP --- (must be checked before SMTP, both use "220" prefix)
    if lower.starts_with("220") && (lower.contains("ftp") || port == 21) {
        let service = if lower.contains("vsftpd") {
            "vsftpd"
        } else if lower.contains("proftpd") {
            "ProFTPD"
        } else if lower.contains("filezilla") {
            "FileZilla FTP"
        } else if lower.contains("pure-ftpd") {
            "Pure-FTPd"
        } else {
            "FTP"
        };
        let version = extract_version_generic(banner);
        return (Some(service.to_string()), version);
    }

    // --- SMTP ---
    if lower.contains("smtp") || lower.starts_with("220 ") || lower.starts_with("250 ") {
        let service = if lower.contains("postfix") {
            "Postfix SMTP"
        } else if lower.contains("exim") {
            "Exim SMTP"
        } else if lower.contains("sendmail") {
            "Sendmail"
        } else if lower.contains("exchange") {
            "Microsoft Exchange"
        } else {
            "SMTP"
        };
        return (Some(service.to_string()), None);
    }

    // --- MySQL ---
    if lower.contains("mysql") || port == 3306 {
        let version = extract_version_generic(banner);
        return (Some("MySQL".to_string()), version);
    }

    // --- PostgreSQL ---
    if lower.contains("postgresql") || port == 5432 {
        return (Some("PostgreSQL".to_string()), None);
    }

    // --- Redis ---
    if lower.contains("redis") || lower.starts_with("-err") || lower.starts_with("+pong") {
        return (Some("Redis".to_string()), extract_version_generic(banner));
    }

    // --- MongoDB ---
    if lower.contains("mongodb") || port == 27017 {
        return (Some("MongoDB".to_string()), None);
    }

    // Fallback: unknown service
    (Some("Unknown Service".to_string()), None)
}

/// Extract version string following a prefix (e.g., "SSH-2.0-OpenSSH_8.9")
fn extract_version_after(banner: &str, prefix: &str) -> Option<String> {
    if let Some(start) = banner.find(prefix) {
        let remainder = &banner[start + prefix.len()..];
        let version: String = remainder
            .chars()
            .take_while(|c| !c.is_ascii_control())
            .collect();
        if !version.is_empty() {
            return Some(version.trim().to_string());
        }
    }
    None
}

/// Extract the value of the `Server:` HTTP header from a banner.
fn extract_server_version(banner: &str) -> Option<String> {
    for line in banner.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") {
            let value = line["server:".len()..].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Generic version extraction: find the first token matching `X.Y.Z` pattern.
fn extract_version_generic(banner: &str) -> Option<String> {
    for token in banner.split_whitespace() {
        let cleaned: String = token
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if cleaned.contains('.') && cleaned.len() >= 3 {
            return Some(cleaned);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_banner_removes_non_printable() {
        let input = b"SSH-2.0-OpenSSH_8.9\x00\x01\x02 extra";
        let result = sanitize_banner(input);
        assert!(result.starts_with("SSH-2.0-OpenSSH_8.9"));
        assert!(result.contains("extra"));
        assert!(!result.contains('\x00'));
    }

    #[test]
    fn test_sanitize_banner_trims() {
        let input = b"  Hello World  ";
        let result = sanitize_banner(input);
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn test_identify_ssh() {
        let (name, version) = identify_service("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4", 22);
        assert_eq!(name.as_deref(), Some("SSH"));
        assert!(version.is_some());
        assert!(version.unwrap().contains("OpenSSH"));
    }

    #[test]
    fn test_identify_http_nginx() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n";
        let (name, version) = identify_service(banner, 80);
        assert_eq!(name.as_deref(), Some("Nginx"));
        assert_eq!(version.as_deref(), Some("nginx/1.18.0"));
    }

    #[test]
    fn test_identify_http_apache() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n\r\n";
        let (name, version) = identify_service(banner, 80);
        assert_eq!(name.as_deref(), Some("Apache"));
        assert!(version.is_some());
    }

    #[test]
    fn test_identify_smtp_postfix() {
        let banner = "220 mail.example.com ESMTP Postfix (Ubuntu)";
        let (name, _) = identify_service(banner, 25);
        assert_eq!(name.as_deref(), Some("Postfix SMTP"));
    }

    #[test]
    fn test_identify_ftp_vsftpd() {
        let banner = "220 (vsFTPd 3.0.5)";
        let (name, version) = identify_service(banner, 21);
        assert_eq!(name.as_deref(), Some("vsftpd"));
        assert_eq!(version.as_deref(), Some("3.0.5"));
    }

    #[test]
    fn test_identify_redis() {
        let (name, _) = identify_service("-ERR wrong number of arguments", 6379);
        assert_eq!(name.as_deref(), Some("Redis"));
    }

    #[test]
    fn test_identify_mysql() {
        let (name, _) = identify_service("5.7.42-MySQL Community Server", 3306);
        assert_eq!(name.as_deref(), Some("MySQL"));
    }

    #[test]
    fn test_identify_empty_banner() {
        let (name, version) = identify_service("", 12345);
        assert!(name.is_none());
        assert!(version.is_none());
    }

    #[test]
    fn test_identify_unknown_service() {
        let (name, _) = identify_service("some random data here", 9999);
        assert_eq!(name.as_deref(), Some("Unknown Service"));
    }

    #[test]
    fn test_extract_version_generic() {
        assert_eq!(
            extract_version_generic("vsftpd 3.0.5"),
            Some("3.0.5".to_string())
        );
        assert_eq!(extract_version_generic("no version here"), None);
    }

    #[test]
    fn test_extract_server_version_header() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n";
        assert_eq!(
            extract_server_version(banner),
            Some("nginx/1.18.0".to_string())
        );
    }

    #[test]
    fn test_probe_selection() {
        let http_probe = get_probe_for_port(80);
        assert_eq!(http_probe.probe_type, ProbeType::HttpGet);

        let ssh_probe = get_probe_for_port(22);
        assert_eq!(ssh_probe.probe_type, ProbeType::Passive);

        let smtp_probe = get_probe_for_port(25);
        assert_eq!(smtp_probe.probe_type, ProbeType::SmtpEhlo);

        let ftp_probe = get_probe_for_port(21);
        assert_eq!(ftp_probe.probe_type, ProbeType::FtpNoop);

        let unknown_probe = get_probe_for_port(55555);
        assert_eq!(unknown_probe.probe_type, ProbeType::GenericProbe);
    }

    #[test]
    fn test_banner_result_display() {
        let result = BannerResult {
            port: 22,
            raw_banner: Some("SSH-2.0-OpenSSH_8.9".to_string()),
            service_name: Some("SSH".to_string()),
            service_version: Some("2.0-OpenSSH_8.9".to_string()),
            probe_used: ProbeType::Passive,
        };
        let display = format!("{result}");
        assert!(display.contains("Port 22"));
        assert!(display.contains("SSH"));
    }

    #[test]
    fn test_probe_type_display() {
        assert_eq!(format!("{}", ProbeType::Passive), "Passive");
        assert_eq!(format!("{}", ProbeType::HttpGet), "HTTP-GET");
        assert_eq!(format!("{}", ProbeType::SmtpEhlo), "SMTP-EHLO");
        assert_eq!(format!("{}", ProbeType::FtpNoop), "FTP-NOOP");
        assert_eq!(format!("{}", ProbeType::GenericProbe), "Generic");
    }
}
