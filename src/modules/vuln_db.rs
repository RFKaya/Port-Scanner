//! Vulnerability Database Module
//!
//! Maps well-known port numbers to their associated security risks and
//! vulnerability information. Provides lookup, search, and risk summary
//! capabilities.

use crate::persistence::models::{RiskLevel, VulnerabilityInfo};

/// Look up known vulnerabilities for a given port number.
///
/// Returns `None` for ports that have no well-known vulnerability associations.
pub fn get_vuln_for_port(port: u16) -> Option<VulnerabilityInfo> {
    match port {
        21 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "Unencrypted FTP".to_string(),
            description: "FTP passes credentials in cleartext. Sensitive data can be intercepted.".to_string(),
        }),
        22 => Some(VulnerabilityInfo {
            risk: RiskLevel::Low,
            name: "SSH Access".to_string(),
            description: "SSH is generally secure but prone to brute-force attacks if not properly hardened.".to_string(),
        }),
        23 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "Telnet Cleartext".to_string(),
            description: "Telnet is highly insecure. All communication, including passwords, is sent in plain text.".to_string(),
        }),
        25 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "SMTP Relay Risk".to_string(),
            description: "Open SMTP relays can be used for spam and phishing campaigns.".to_string(),
        }),
        53 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "DNS Zone Transfer".to_string(),
            description: "Misconfigured DNS servers may allow zone transfers, leaking internal network details.".to_string(),
        }),
        69 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "TFTP No Authentication".to_string(),
            description: "TFTP has no authentication mechanism. Attackers can read/write files on the server.".to_string(),
        }),
        80 => Some(VulnerabilityInfo {
            risk: RiskLevel::Low,
            name: "Unencrypted HTTP".to_string(),
            description: "HTTP traffic is not encrypted. Use HTTPS (443) for sensitive data.".to_string(),
        }),
        110 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "POP3 Cleartext".to_string(),
            description: "POP3 transmits emails and credentials in cleartext. Use POP3S (995) instead.".to_string(),
        }),
        111 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "RPCBind Exposure".to_string(),
            description: "RPCBind can expose RPC services to attackers, enabling enumeration and exploitation.".to_string(),
        }),
        135 | 139 | 445 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "SMB/EternalBlue Risk".to_string(),
            description: "SMB services are primary targets for worms and ransomware like WannaCry (MS17-010).".to_string(),
        }),
        143 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "IMAP Cleartext".to_string(),
            description: "IMAP transmits emails and credentials in cleartext. Use IMAPS (993) instead.".to_string(),
        }),
        161 | 162 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "SNMP Community Strings".to_string(),
            description: "SNMP with default community strings (public/private) allows full device enumeration and configuration changes.".to_string(),
        }),
        389 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "LDAP Cleartext".to_string(),
            description: "Unencrypted LDAP can expose directory information and credentials. Use LDAPS (636).".to_string(),
        }),
        443 => Some(VulnerabilityInfo {
            risk: RiskLevel::Low,
            name: "HTTPS Endpoint".to_string(),
            description: "HTTPS is encrypted but may have TLS misconfiguration or certificate issues.".to_string(),
        }),
        512..=514 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "Berkeley r-commands".to_string(),
            description: "rexec/rlogin/rsh use host-based authentication and transmit data in cleartext. Extremely dangerous.".to_string(),
        }),
        1080 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "SOCKS Proxy Open".to_string(),
            description: "An open SOCKS proxy can be abused for anonymous traffic relay and network pivoting.".to_string(),
        }),
        1433 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "MSSQL Remote Access".to_string(),
            description: "Database servers exposed to the internet are high-value targets for data theft.".to_string(),
        }),
        1521 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "Oracle DB Remote Access".to_string(),
            description: "Oracle databases exposed to the internet are high-value targets with known exploits.".to_string(),
        }),
        2049 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "NFS Share Exposure".to_string(),
            description: "NFS shares accessible from the internet can leak sensitive files and enable unauthorized access.".to_string(),
        }),
        2375 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "Docker API Unprotected".to_string(),
            description: "Unsecured Docker API allows full container and host compromise with remote code execution.".to_string(),
        }),
        3306 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "MySQL Remote Access".to_string(),
            description: "Direct internet access to MySQL can lead to data breaches if weak passwords are used.".to_string(),
        }),
        3389 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "RDP / BlueKeep Risk".to_string(),
            description: "Remote Desktop (RDP) is a frequent target for brute-force and RCE vulnerabilities like BlueKeep.".to_string(),
        }),
        4444 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "Metasploit Default Shell".to_string(),
            description: "Port 4444 is the default Metasploit reverse shell port. An active listener here indicates compromise.".to_string(),
        }),
        5432 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "PostgreSQL Risk".to_string(),
            description: "Postgres exposure should be limited to internal networks only.".to_string(),
        }),
        5900 | 5901 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "VNC Access".to_string(),
            description: "VNC is often targeted for unauthorized remote control if weak authentication is used.".to_string(),
        }),
        5984 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "CouchDB Unauthenticated".to_string(),
            description: "CouchDB may allow unauthenticated access to databases, including admin operations.".to_string(),
        }),
        5985 | 5986 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "WinRM Remote Management".to_string(),
            description: "Windows Remote Management allows remote command execution. Ensure strong authentication.".to_string(),
        }),
        6379 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "Unauthenticated Redis".to_string(),
            description: "Redis often has no password by default, allowing full RCE if exposed to the internet.".to_string(),
        }),
        6667 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "IRC Server".to_string(),
            description: "IRC servers can be used for botnet command-and-control communications.".to_string(),
        }),
        8080 | 8443 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "Admin Interface".to_string(),
            description: "Management panels often use these ports and may have default credentials.".to_string(),
        }),
        8888 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "Jupyter Notebook".to_string(),
            description: "Unprotected Jupyter notebooks allow arbitrary code execution on the server.".to_string(),
        }),
        9090 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "Prometheus/Cockpit".to_string(),
            description: "Monitoring dashboards may expose sensitive system metrics and configuration.".to_string(),
        }),
        9200 | 9300 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "Elasticsearch No-Auth".to_string(),
            description: "Elasticsearch often runs without authentication, exposing all indexed data to the internet.".to_string(),
        }),
        11211 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "Memcached Amplification".to_string(),
            description: "Exposed Memcached servers can be abused for DDoS amplification attacks.".to_string(),
        }),
        27017 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "MongoDB No-Auth".to_string(),
            description: "Old MongoDB versions or misconfigurations allow full data access without a password.".to_string(),
        }),
        50000 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "SAP/Jenkins Exposure".to_string(),
            description: "Port 50000 is used by SAP and Jenkins. Exposed instances may allow unauthorized access.".to_string(),
        }),
        _ => None,
    }
}

/// Get remediation advice for a given port.
pub fn get_remediation(port: u16) -> Option<String> {
    match port {
        21 => Some(
            "Replace FTP with SFTP (SSH File Transfer) or FTPS. Disable anonymous access."
                .to_string(),
        ),
        22 => Some(
            "Disable password authentication; use key-based auth. Implement fail2ban.".to_string(),
        ),
        23 => Some("Disable Telnet entirely. Replace with SSH for remote access.".to_string()),
        25 => {
            Some("Restrict relay to authorized senders. Enable STARTTLS and SPF/DKIM.".to_string())
        }
        53 => Some(
            "Restrict zone transfers to authorized secondary DNS servers only (allow-transfer)."
                .to_string(),
        ),
        80 => Some("Redirect all HTTP traffic to HTTPS. Implement HSTS headers.".to_string()),
        110 => Some("Replace POP3 with POP3S (port 995) or use IMAPS.".to_string()),
        135 | 139 | 445 => Some(
            "Block SMB ports at the firewall. Apply all MS17-010 patches. Disable SMBv1."
                .to_string(),
        ),
        143 => Some("Replace IMAP with IMAPS (port 993). Enforce TLS connections.".to_string()),
        161 | 162 => Some(
            "Change default SNMP community strings. Use SNMPv3 with authentication.".to_string(),
        ),
        389 => {
            Some("Use LDAPS (port 636) with TLS. Restrict access to internal networks.".to_string())
        }
        1433 => {
            Some("Use Windows Firewall to restrict access. Enable SQL Server Audit.".to_string())
        }
        2375 => {
            Some("Enable TLS for Docker API. Use Docker socket with unix socket only.".to_string())
        }
        3306 => Some(
            "Bind MySQL to localhost (bind-address=127.0.0.1). Use strong passwords.".to_string(),
        ),
        3389 => Some("Enable NLA. Use VPN for RDP access. Apply all BlueKeep patches.".to_string()),
        5432 => Some("Configure pg_hba.conf to restrict connections. Use SSL.".to_string()),
        5900 | 5901 => Some("Use SSH tunneling for VNC. Set strong VNC passwords.".to_string()),
        6379 => Some(
            "Set a strong password (requirepass). Bind to localhost. Disable dangerous commands."
                .to_string(),
        ),
        9200 | 9300 => {
            Some("Enable X-Pack Security or SearchGuard. Bind to localhost.".to_string())
        }
        27017 => Some("Enable MongoDB authentication (--auth). Bind to localhost.".to_string()),
        _ => None,
    }
}

/// Search for vulnerabilities by service name (case-insensitive).
pub fn search_by_service(query: &str) -> Vec<(u16, VulnerabilityInfo)> {
    let query_lower = query.to_lowercase();
    let ports_to_check: Vec<u16> = vec![
        21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 139, 143, 161, 162, 389, 443, 445, 512, 513,
        514, 1080, 1433, 1521, 2049, 2375, 3306, 3389, 4444, 5432, 5900, 5901, 5984, 5985, 5986,
        6379, 6667, 8080, 8443, 8888, 9090, 9200, 9300, 11211, 27017, 50000,
    ];

    let mut results = Vec::new();
    for port in ports_to_check {
        if let Some(vuln) = get_vuln_for_port(port) {
            if vuln.name.to_lowercase().contains(&query_lower)
                || vuln.description.to_lowercase().contains(&query_lower)
            {
                results.push((port, vuln));
            }
        }
    }
    results
}

/// Generate a risk summary across all known vulnerable ports.
pub fn get_risk_summary() -> RiskSummary {
    let ports_to_check: Vec<u16> = vec![
        21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 139, 143, 161, 162, 389, 443, 445, 512, 513,
        514, 1080, 1433, 1521, 2049, 2375, 3306, 3389, 4444, 5432, 5900, 5901, 5984, 5985, 5986,
        6379, 6667, 8080, 8443, 8888, 9090, 9200, 9300, 11211, 27017, 50000,
    ];

    let mut summary = RiskSummary::default();
    for port in ports_to_check {
        if let Some(vuln) = get_vuln_for_port(port) {
            summary.total += 1;
            match vuln.risk {
                RiskLevel::Critical => summary.critical += 1,
                RiskLevel::High => summary.high += 1,
                RiskLevel::Medium => summary.medium += 1,
                RiskLevel::Low => summary.low += 1,
                RiskLevel::None => {}
            }
        }
    }
    summary
}

/// Summary of all vulnerability entries in the database.
#[derive(Debug, Default)]
pub struct RiskSummary {
    /// Total number of vulnerability entries.
    pub total: usize,
    /// Number of critical-risk entries.
    pub critical: usize,
    /// Number of high-risk entries.
    pub high: usize,
    /// Number of medium-risk entries.
    pub medium: usize,
    /// Number of low-risk entries.
    pub low: usize,
}

impl std::fmt::Display for RiskSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VulnDB: {} entries (Critical: {}, High: {}, Medium: {}, Low: {})",
            self.total, self.critical, self.high, self.medium, self.low
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::models::RiskLevel;

    // --- get_vuln_for_port ---

    #[test]
    fn test_get_vuln_for_port_telnet() {
        let vuln = get_vuln_for_port(23).unwrap();
        assert_eq!(vuln.risk, RiskLevel::Critical);
        assert!(vuln.name.contains("Telnet"));
    }

    #[test]
    fn test_get_vuln_for_port_ssh() {
        let vuln = get_vuln_for_port(22).unwrap();
        assert_eq!(vuln.risk, RiskLevel::Low);
        assert!(vuln.name.contains("SSH"));
    }

    #[test]
    fn test_get_vuln_for_port_ftp() {
        let vuln = get_vuln_for_port(21).unwrap();
        assert_eq!(vuln.risk, RiskLevel::Medium);
    }

    #[test]
    fn test_get_vuln_for_port_smb_ports() {
        assert!(get_vuln_for_port(135).is_some());
        assert!(get_vuln_for_port(139).is_some());
        assert!(get_vuln_for_port(445).is_some());
        assert_eq!(get_vuln_for_port(445).unwrap().risk, RiskLevel::Critical);
    }

    #[test]
    fn test_get_vuln_for_port_redis() {
        let vuln = get_vuln_for_port(6379).unwrap();
        assert_eq!(vuln.risk, RiskLevel::Critical);
    }

    #[test]
    fn test_get_vuln_for_port_mongodb() {
        let vuln = get_vuln_for_port(27017).unwrap();
        assert_eq!(vuln.risk, RiskLevel::Critical);
    }

    #[test]
    fn test_get_vuln_for_port_elasticsearch() {
        assert!(get_vuln_for_port(9200).is_some());
        assert!(get_vuln_for_port(9300).is_some());
    }

    #[test]
    fn test_get_vuln_for_port_docker() {
        let vuln = get_vuln_for_port(2375).unwrap();
        assert_eq!(vuln.risk, RiskLevel::Critical);
    }

    #[test]
    fn test_get_vuln_for_port_metasploit() {
        let vuln = get_vuln_for_port(4444).unwrap();
        assert_eq!(vuln.risk, RiskLevel::Critical);
    }

    #[test]
    fn test_get_vuln_for_port_snmp() {
        assert!(get_vuln_for_port(161).is_some());
        assert!(get_vuln_for_port(162).is_some());
    }

    #[test]
    fn test_get_vuln_for_port_rpc() {
        let vuln = get_vuln_for_port(111).unwrap();
        assert_eq!(vuln.risk, RiskLevel::High);
    }

    #[test]
    fn test_get_vuln_for_port_unknown() {
        assert!(get_vuln_for_port(12345).is_none());
        assert!(get_vuln_for_port(65535).is_none());
    }

    // --- get_remediation ---

    #[test]
    fn test_remediation_exists_for_critical() {
        assert!(get_remediation(23).is_some());
        assert!(get_remediation(445).is_some());
        assert!(get_remediation(6379).is_some());
    }

    #[test]
    fn test_remediation_content() {
        let rem = get_remediation(23).unwrap();
        assert!(rem.contains("SSH"));
    }

    #[test]
    fn test_remediation_unknown_port() {
        assert!(get_remediation(12345).is_none());
    }

    // --- search_by_service ---

    #[test]
    fn test_search_by_service_ftp() {
        let results = search_by_service("FTP");
        assert!(!results.is_empty());
        assert!(results.iter().any(|(port, _)| *port == 21));
    }

    #[test]
    fn test_search_by_service_case_insensitive() {
        let upper = search_by_service("REDIS");
        let lower = search_by_service("redis");
        assert_eq!(upper.len(), lower.len());
    }

    #[test]
    fn test_search_by_service_no_match() {
        let results = search_by_service("zzz_nonexistent_service_zzz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_service_smtp() {
        let results = search_by_service("SMTP");
        assert!(results.iter().any(|(port, _)| *port == 25));
    }

    // --- get_risk_summary ---

    #[test]
    fn test_risk_summary() {
        let summary = get_risk_summary();
        assert!(summary.total > 20);
        assert!(summary.critical > 0);
        assert!(summary.high > 0);
        assert!(summary.medium > 0);
        assert!(summary.low > 0);
    }

    #[test]
    fn test_risk_summary_display() {
        let summary = get_risk_summary();
        let display = format!("{summary}");
        assert!(display.contains("VulnDB"));
        assert!(display.contains("Critical"));
    }

    #[test]
    fn test_risk_summary_counts_add_up() {
        let summary = get_risk_summary();
        let sum = summary.critical + summary.high + summary.medium + summary.low;
        assert_eq!(summary.total, sum);
    }
}
