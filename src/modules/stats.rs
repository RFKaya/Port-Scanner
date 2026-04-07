//! Scan Statistics & Reporting Module
//!
//! Collects, analyzes, and reports scan statistics such as port counts,
//! timing data, throughput rates, and risk assessments.

use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::persistence::models::{PortResult, PortStatus, ScanResult};

/// Aggregated statistics for a completed scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    /// Target that was scanned.
    pub target: String,
    /// Total number of ports scanned.
    pub total_ports: usize,
    /// Number of open ports found.
    pub open_ports: usize,
    /// Number of closed ports found.
    pub closed_ports: usize,
    /// Number of filtered ports found.
    pub filtered_ports: usize,
    /// Total scan duration in milliseconds.
    pub duration_ms: u64,
    /// Average scan rate (ports per second).
    pub scan_rate: f64,
    /// Number of ports with vulnerabilities.
    pub vuln_count: usize,
    /// Number of critical-risk vulnerabilities.
    pub critical_count: usize,
    /// Number of high-risk vulnerabilities.
    pub high_count: usize,
    /// Number of medium-risk vulnerabilities.
    pub medium_count: usize,
    /// Number of low-risk vulnerabilities.
    pub low_count: usize,
    /// Overall risk assessment for this scan.
    pub risk_assessment: RiskAssessment,
}

impl fmt::Display for ScanStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Scan Statistics for {} ===", self.target)?;
        writeln!(f, "Total Ports: {}", self.total_ports)?;
        writeln!(
            f,
            "Open: {} | Closed: {} | Filtered: {}",
            self.open_ports, self.closed_ports, self.filtered_ports
        )?;
        writeln!(
            f,
            "Duration: {}ms ({:.1} ports/sec)",
            self.duration_ms, self.scan_rate
        )?;
        writeln!(
            f,
            "Vulnerabilities: {} total ({} critical, {} high)",
            self.vuln_count, self.critical_count, self.high_count
        )?;
        write!(f, "Risk Assessment: {}", self.risk_assessment)
    }
}

/// Overall risk assessment based on vulnerability findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskAssessment {
    /// No vulnerabilities detected.
    Clean,
    /// Only informational or low-risk findings.
    Low,
    /// Medium-risk vulnerabilities present.
    Medium,
    /// High-risk vulnerabilities present.
    High,
    /// Critical vulnerabilities detected — immediate action recommended.
    Critical,
}

impl fmt::Display for RiskAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskAssessment::Clean => write!(f, "✅ Clean"),
            RiskAssessment::Low => write!(f, "🔵 Low Risk"),
            RiskAssessment::Medium => write!(f, "🟡 Medium Risk"),
            RiskAssessment::High => write!(f, "🟠 High Risk"),
            RiskAssessment::Critical => write!(f, "🔴 Critical Risk"),
        }
    }
}

/// Helper for measuring scan duration with lap support.
pub struct ScanTimer {
    start: Instant,
    laps: Vec<(String, Duration)>,
}

impl ScanTimer {
    /// Start a new scan timer.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
            laps: Vec::new(),
        }
    }

    /// Record a named lap time.
    pub fn lap(&mut self, name: &str) {
        self.laps.push((name.to_string(), self.start.elapsed()));
    }

    /// Get total elapsed time.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get elapsed time in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Get all recorded laps.
    pub fn laps(&self) -> &[(String, Duration)] {
        &self.laps
    }
}

impl fmt::Display for ScanTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScanTimer(elapsed={}ms, laps={})",
            self.elapsed_ms(),
            self.laps.len()
        )
    }
}

/// Live statistics collector that accumulates results during a streaming scan.
#[derive(Debug, Default)]
pub struct StatisticsCollector {
    pub open: usize,
    pub closed: usize,
    pub filtered: usize,
    pub vuln_critical: usize,
    pub vuln_high: usize,
    pub vuln_medium: usize,
    pub vuln_low: usize,
}

impl StatisticsCollector {
    /// Create a new empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a single port result.
    pub fn record(&mut self, result: &PortResult) {
        match result.status {
            PortStatus::Open => self.open += 1,
            PortStatus::Closed => self.closed += 1,
            PortStatus::Filtered => self.filtered += 1,
        }

        if let Some(ref vuln) = result.vulnerability {
            match vuln.risk {
                crate::persistence::models::RiskLevel::Critical => self.vuln_critical += 1,
                crate::persistence::models::RiskLevel::High => self.vuln_high += 1,
                crate::persistence::models::RiskLevel::Medium => self.vuln_medium += 1,
                crate::persistence::models::RiskLevel::Low => self.vuln_low += 1,
                crate::persistence::models::RiskLevel::None => {}
            }
        }
    }

    /// Get total number of ports recorded.
    pub fn total(&self) -> usize {
        self.open + self.closed + self.filtered
    }

    /// Get total vulnerability count.
    pub fn total_vulns(&self) -> usize {
        self.vuln_critical + self.vuln_high + self.vuln_medium + self.vuln_low
    }
}

impl fmt::Display for StatisticsCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Stats(total={}, open={}, vulns={})",
            self.total(),
            self.open,
            self.total_vulns()
        )
    }
}

/// Calculate scan rate in ports per second.
pub fn calculate_scan_rate(port_count: usize, duration: Duration) -> f64 {
    let secs = duration.as_secs_f64();
    if secs < 0.001 {
        return 0.0;
    }
    port_count as f64 / secs
}

/// Determine the overall risk assessment from vulnerability counts.
pub fn assess_risk(critical: usize, high: usize, medium: usize, _low: usize) -> RiskAssessment {
    if critical > 0 {
        RiskAssessment::Critical
    } else if high > 0 {
        RiskAssessment::High
    } else if medium > 0 {
        RiskAssessment::Medium
    } else if _low > 0 {
        RiskAssessment::Low
    } else {
        RiskAssessment::Clean
    }
}

/// Build a complete [`ScanStatistics`] from a [`ScanResult`] and a duration.
pub fn build_statistics(result: &ScanResult, duration: Duration) -> ScanStatistics {
    let mut collector = StatisticsCollector::new();
    for port in &result.ports {
        collector.record(port);
    }

    let total = collector.total();
    let scan_rate = calculate_scan_rate(total, duration);
    let risk = assess_risk(
        collector.vuln_critical,
        collector.vuln_high,
        collector.vuln_medium,
        collector.vuln_low,
    );

    ScanStatistics {
        target: result.target.clone(),
        total_ports: total,
        open_ports: collector.open,
        closed_ports: collector.closed,
        filtered_ports: collector.filtered,
        duration_ms: duration.as_millis() as u64,
        scan_rate,
        vuln_count: collector.total_vulns(),
        critical_count: collector.vuln_critical,
        high_count: collector.vuln_high,
        medium_count: collector.vuln_medium,
        low_count: collector.vuln_low,
        risk_assessment: risk,
    }
}

/// Generate a human-readable summary report string.
pub fn generate_summary_report(stats: &ScanStatistics) -> String {
    let mut report = String::new();
    report.push_str("╔══════════════════════════════════════════════╗\n");
    report.push_str("║         SCAN SUMMARY REPORT                 ║\n");
    report.push_str("╠══════════════════════════════════════════════╣\n");
    report.push_str(&format!("║  Target: {:<35} ║\n", stats.target));
    report.push_str(&format!("║  Total Ports: {:<30} ║\n", stats.total_ports));
    report.push_str(&format!("║  Open: {:<37} ║\n", stats.open_ports));
    report.push_str(&format!("║  Closed: {:<35} ║\n", stats.closed_ports));
    report.push_str(&format!("║  Filtered: {:<33} ║\n", stats.filtered_ports));
    report.push_str(&format!(
        "║  Duration: {:<33} ║\n",
        format!("{}ms", stats.duration_ms)
    ));
    report.push_str(&format!(
        "║  Rate: {:<37} ║\n",
        format!("{:.1} ports/sec", stats.scan_rate)
    ));
    report.push_str("╠══════════════════════════════════════════════╣\n");
    report.push_str(&format!("║  Vulnerabilities: {:<26} ║\n", stats.vuln_count));
    report.push_str(&format!("║  Critical: {:<33} ║\n", stats.critical_count));
    report.push_str(&format!("║  High: {:<37} ║\n", stats.high_count));
    report.push_str(&format!("║  Medium: {:<35} ║\n", stats.medium_count));
    report.push_str(&format!("║  Low: {:<38} ║\n", stats.low_count));
    report.push_str("╠══════════════════════════════════════════════╣\n");
    report.push_str(&format!("║  Risk: {:<37} ║\n", stats.risk_assessment));
    report.push_str("╚══════════════════════════════════════════════╝\n");
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::models::{PortResult, PortStatus, RiskLevel, VulnerabilityInfo};

    fn make_port(port: u16, status: PortStatus, vuln: Option<VulnerabilityInfo>) -> PortResult {
        PortResult {
            port,
            protocol: "TCP".to_string(),
            status,
            vulnerability: vuln,
        }
    }

    #[test]
    fn test_statistics_collector_empty() {
        let collector = StatisticsCollector::new();
        assert_eq!(collector.total(), 0);
        assert_eq!(collector.total_vulns(), 0);
    }

    #[test]
    fn test_statistics_collector_record() {
        let mut collector = StatisticsCollector::new();
        collector.record(&make_port(80, PortStatus::Open, None));
        collector.record(&make_port(81, PortStatus::Closed, None));
        collector.record(&make_port(82, PortStatus::Filtered, None));
        assert_eq!(collector.total(), 3);
        assert_eq!(collector.open, 1);
        assert_eq!(collector.closed, 1);
        assert_eq!(collector.filtered, 1);
    }

    #[test]
    fn test_statistics_collector_with_vulns() {
        let mut collector = StatisticsCollector::new();
        let vuln = VulnerabilityInfo {
            risk: RiskLevel::Critical,
            name: "Test".to_string(),
            description: "Test vulnerability".to_string(),
        };
        collector.record(&make_port(23, PortStatus::Open, Some(vuln)));
        assert_eq!(collector.vuln_critical, 1);
        assert_eq!(collector.total_vulns(), 1);
    }

    #[test]
    fn test_assess_risk_critical() {
        assert_eq!(assess_risk(1, 0, 0, 0), RiskAssessment::Critical);
    }

    #[test]
    fn test_assess_risk_high() {
        assert_eq!(assess_risk(0, 2, 0, 0), RiskAssessment::High);
    }

    #[test]
    fn test_assess_risk_medium() {
        assert_eq!(assess_risk(0, 0, 1, 0), RiskAssessment::Medium);
    }

    #[test]
    fn test_assess_risk_low() {
        assert_eq!(assess_risk(0, 0, 0, 3), RiskAssessment::Low);
    }

    #[test]
    fn test_assess_risk_clean() {
        assert_eq!(assess_risk(0, 0, 0, 0), RiskAssessment::Clean);
    }

    #[test]
    fn test_calculate_scan_rate() {
        let rate = calculate_scan_rate(1000, Duration::from_secs(2));
        assert!((rate - 500.0).abs() < 1.0);
    }

    #[test]
    fn test_calculate_scan_rate_zero_duration() {
        assert_eq!(calculate_scan_rate(100, Duration::ZERO), 0.0);
    }

    #[test]
    fn test_build_statistics() {
        let result = ScanResult {
            target: "localhost".to_string(),
            ports: vec![
                make_port(
                    80,
                    PortStatus::Open,
                    Some(VulnerabilityInfo {
                        risk: RiskLevel::Low,
                        name: "HTTP".to_string(),
                        description: "Unencrypted".to_string(),
                    }),
                ),
                make_port(443, PortStatus::Closed, None),
            ],
        };
        let stats = build_statistics(&result, Duration::from_millis(500));
        assert_eq!(stats.total_ports, 2);
        assert_eq!(stats.open_ports, 1);
        assert_eq!(stats.closed_ports, 1);
        assert_eq!(stats.low_count, 1);
        assert_eq!(stats.risk_assessment, RiskAssessment::Low);
    }

    #[test]
    fn test_generate_summary_report() {
        let stats = ScanStatistics {
            target: "test".to_string(),
            total_ports: 100,
            open_ports: 5,
            closed_ports: 90,
            filtered_ports: 5,
            duration_ms: 1000,
            scan_rate: 100.0,
            vuln_count: 2,
            critical_count: 1,
            high_count: 1,
            medium_count: 0,
            low_count: 0,
            risk_assessment: RiskAssessment::Critical,
        };
        let report = generate_summary_report(&stats);
        assert!(report.contains("SCAN SUMMARY REPORT"));
        assert!(report.contains("test"));
    }

    #[test]
    fn test_scan_timer() {
        let mut timer = ScanTimer::start();
        std::thread::sleep(Duration::from_millis(10));
        timer.lap("phase1");
        assert!(timer.elapsed_ms() >= 10);
        assert_eq!(timer.laps().len(), 1);
    }

    #[test]
    fn test_scan_timer_display() {
        let timer = ScanTimer::start();
        let display = format!("{timer}");
        assert!(display.contains("ScanTimer"));
    }

    #[test]
    fn test_risk_assessment_display() {
        assert!(format!("{}", RiskAssessment::Critical).contains("Critical"));
        assert!(format!("{}", RiskAssessment::Clean).contains("Clean"));
    }

    #[test]
    fn test_statistics_collector_display() {
        let mut c = StatisticsCollector::new();
        c.record(&make_port(80, PortStatus::Open, None));
        let d = format!("{c}");
        assert!(d.contains("total=1"));
    }

    #[test]
    fn test_scan_statistics_display() {
        let stats = ScanStatistics {
            target: "localhost".to_string(),
            total_ports: 10,
            open_ports: 2,
            closed_ports: 7,
            filtered_ports: 1,
            duration_ms: 100,
            scan_rate: 100.0,
            vuln_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            risk_assessment: RiskAssessment::Clean,
        };
        let display = format!("{stats}");
        assert!(display.contains("localhost"));
    }
}
