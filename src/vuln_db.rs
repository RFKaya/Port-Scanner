use crate::models::{RiskLevel, VulnerabilityInfo};

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
        80 => Some(VulnerabilityInfo {
            risk: RiskLevel::Low,
            name: "Unencrypted HTTP".to_string(),
            description: "HTTP traffic is not encrypted. Use HTTPS (443) for sensitive data.".to_string(),
        }),
        135 | 139 | 445 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "SMB/EternalBlue Risk".to_string(),
            description: "SMB services are primary targets for worms and ransomware like WannaCry (MS17-010).".to_string(),
        }),
        1433 => Some(VulnerabilityInfo {
            risk: RiskLevel::High,
            name: "MSSQL Remote Access".to_string(),
            description: "Database servers exposed to the internet are high-value targets for data theft.".to_string(),
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
        6379 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "Unauthenticated Redis".to_string(),
            description: "Redis often has no password by default, allowing full RCE if exposed to the internet.".to_string(),
        }),
        8080 | 8443 => Some(VulnerabilityInfo {
            risk: RiskLevel::Medium,
            name: "Admin Interface".to_string(),
            description: "Management panels often use these ports and may have default credentials.".to_string(),
        }),
        27017 => Some(VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "MongoDB No-Auth".to_string(),
            description: "Old MongoDB versions or misconfigurations allow full data access without a password.".to_string(),
        }),
        _ => None,
    }
}
