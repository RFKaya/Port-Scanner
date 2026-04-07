//! Web Server Module
//!
//! Axum-based HTTP server powering the Web UI and REST API.
//! Provides endpoints for scanning, history management, statistics,
//! configuration, and vulnerability database search.

use crate::modules::{network, stats, vuln_db};
use crate::persistence::models::ScanResult;
use crate::Result;
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        Html,
    },
    routing::{delete, get, post},
    Json, Router,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::time::Duration;
use tower_http::cors::CorsLayer;

/// Incoming scan request payload from the Web UI or API client.
#[derive(Deserialize)]
pub struct ScanRequest {
    target: String,
    range: String,
    #[serde(default)]
    scan_type: String, // "tcp", "syn", "udp"
    #[serde(default = "default_timeout")]
    timeout: u64,
    #[serde(default = "default_concurrency")]
    concurrency: usize,
}

fn default_timeout() -> u64 {
    1000
}
fn default_concurrency() -> usize {
    500
}

/// Query parameters for vulnerability search.
#[derive(Deserialize)]
struct VulnSearchQuery {
    q: String,
}

/// Response for the `/api/stats` endpoint.
#[derive(Serialize)]
struct AppStats {
    /// Total number of saved scan files.
    total_scans: usize,
    /// Application version.
    version: String,
    /// Vulnerability database summary.
    vuln_db_entries: usize,
    /// Critical vulnerability count in DB.
    vuln_critical: usize,
    /// High vulnerability count in DB.
    vuln_high: usize,
    /// Server status.
    status: String,
}

/// Response for the `/api/config` endpoint.
#[derive(Serialize)]
struct ConfigResponse {
    /// Scan engine configuration.
    scan: ScanConfigResponse,
    /// Server configuration.
    server: ServerConfigResponse,
}

#[derive(Serialize)]
struct ScanConfigResponse {
    default_timeout_ms: u64,
    default_concurrency: usize,
    max_concurrency_tcp: usize,
    max_concurrency_syn: usize,
    max_concurrency_udp: usize,
    default_port_range: String,
}

#[derive(Serialize)]
struct ServerConfigResponse {
    version: String,
    cors_enabled: bool,
}

/// IP classification result for the API.
#[derive(Serialize)]
struct IpClassifyResponse {
    ip: String,
    classification: String,
    is_private: bool,
}

/// Vulnerability search result for the API.
#[derive(Serialize)]
struct VulnSearchResult {
    port: u16,
    name: String,
    risk: String,
    description: String,
    remediation: Option<String>,
}

/// Scan statistics response from a history file.
#[derive(Serialize)]
struct ScanStatsResponse {
    target: String,
    total_ports: usize,
    open_ports: usize,
    closed_ports: usize,
    filtered_ports: usize,
    vuln_count: usize,
    risk_assessment: String,
}

/// Start the Axum web server on the specified port.
///
/// Sets up all routes, middleware, and begins listening for connections.
pub async fn start_server(port: u16) {
    let app = Router::new()
        // Static / UI
        .route("/", get(index_handler))
        // Scan API
        .route("/api/scan", post(scan_handler))
        .route("/api/scan/stream", post(scan_stream_handler))
        // History API
        .route("/api/history", get(list_history_handler))
        .route("/api/history/:filename", get(get_history_handler))
        .route("/api/history/:filename", delete(delete_history_handler))
        .route("/api/history/:filename/stats", get(history_stats_handler))
        // Stats & Config API
        .route("/api/stats", get(stats_handler))
        .route("/api/config", get(config_handler))
        .route("/api/health", get(health_handler))
        // Utility API endpoints
        .route("/api/classify/:target", get(classify_handler))
        .route("/api/vuln/search", get(vuln_search_handler))
        .route("/api/vuln/:port", get(vuln_port_handler))
        // Middleware
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    // Premium Console Log
    println!("\x1b[1;34m========================================================\x1b[0m");
    println!("\x1b[1;32m   🛡️  SecOps Port Scanner - Web Interface Started   \x1b[0m");
    println!("\x1b[1;34m========================================================\x1b[0m");
    println!("\x1b[1;36m   🌐 URL: \x1b[4;36mhttp://{}\x1b[0m", addr);
    println!("\x1b[1;36m   🔌 Port: \x1b[1;33m{}\x1b[0m", port);
    println!(
        "\x1b[1;36m   📊 API:  \x1b[4;36mhttp://{}/api/stats\x1b[0m",
        addr
    );
    println!("\x1b[1;34m========================================================\x1b[0m");

    tracing::info!("Server running on http://{addr}");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {addr}: {e}");
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Server error: {e}");
    }
}

/// Serve the embedded index.html file.
async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../public/index.html"))
}

/// Health check endpoint — always returns 200 OK.
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Full scan endpoint — performs a complete scan and returns all results at once.
async fn scan_handler(Json(payload): Json<ScanRequest>) -> Result<Json<ScanResult>> {
    let syn = payload.scan_type == "syn";
    let udp = payload.scan_type == "udp";

    let result = crate::run_port_scan_logic(
        payload.target,
        payload.range,
        syn,
        udp,
        payload.timeout,
        payload.concurrency,
    )
    .await?;

    result.save_to_file()?;

    Ok(Json(result))
}

/// Streaming scan endpoint — returns results via Server-Sent Events as they arrive.
async fn scan_stream_handler(
    Json(payload): Json<ScanRequest>,
) -> Sse<impl futures::Stream<Item = std::result::Result<Event, Infallible>>> {
    let syn = payload.scan_type == "syn";
    let udp = payload.scan_type == "udp";

    let target_save = payload.target.clone();
    let range_save = payload.range.clone();
    let timeout_save = payload.timeout;

    let stream = crate::run_port_scan_logic_stream(
        payload.target,
        payload.range,
        syn,
        udp,
        payload.timeout,
        payload.concurrency,
    )
    .await;

    // Background task to persist the complete scan
    tokio::spawn(async move {
        if let Ok(result) = crate::run_port_scan_logic(
            target_save,
            range_save,
            syn,
            udp,
            timeout_save,
            payload.concurrency,
        )
        .await
        {
            let _ = result.save_to_file();
        }
    });

    let event_stream = stream.map(|res| {
        let json = serde_json::to_string(&res).unwrap_or_default();
        Ok(Event::default().data(json))
    });

    Sse::new(event_stream)
}

/// List all scan history files (sorted newest first).
async fn list_history_handler() -> Json<Vec<String>> {
    let mut history = Vec::new();
    if let Ok(entries) = fs::read_dir("scans") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if std::path::Path::new(&name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
                {
                    history.push(name);
                }
            }
        }
    }
    history.sort_by(|a, b| b.cmp(a));
    Json(history)
}

/// Retrieve a specific scan history file by filename.
async fn get_history_handler(Path(filename): Path<String>) -> Result<Json<ScanResult>> {
    validate_filename(&filename)?;
    let path = format!("scans/{filename}");
    let content = fs::read_to_string(path)?;
    let result = serde_json::from_str::<ScanResult>(&content)?;
    Ok(Json(result))
}

/// Delete a specific scan history file.
async fn delete_history_handler(Path(filename): Path<String>) -> Result<StatusCode> {
    validate_filename(&filename)?;
    let path = format!("scans/{filename}");
    fs::remove_file(path)?;
    Ok(StatusCode::OK)
}

/// Get statistics for a specific scan history file.
async fn history_stats_handler(Path(filename): Path<String>) -> Result<Json<ScanStatsResponse>> {
    validate_filename(&filename)?;
    let path = format!("scans/{filename}");
    let content = fs::read_to_string(path)?;
    let result = serde_json::from_str::<ScanResult>(&content)?;

    let scan_stats = stats::build_statistics(&result, Duration::from_secs(0));

    Ok(Json(ScanStatsResponse {
        target: scan_stats.target,
        total_ports: scan_stats.total_ports,
        open_ports: scan_stats.open_ports,
        closed_ports: scan_stats.closed_ports,
        filtered_ports: scan_stats.filtered_ports,
        vuln_count: scan_stats.vuln_count,
        risk_assessment: format!("{}", scan_stats.risk_assessment),
    }))
}

/// Application statistics endpoint.
async fn stats_handler() -> Json<AppStats> {
    let total_scans = count_scan_files();
    let vuln_summary = vuln_db::get_risk_summary();

    Json(AppStats {
        total_scans,
        version: env!("CARGO_PKG_VERSION").to_string(),
        vuln_db_entries: vuln_summary.total,
        vuln_critical: vuln_summary.critical,
        vuln_high: vuln_summary.high,
        status: "operational".to_string(),
    })
}

/// Application configuration endpoint (read-only).
async fn config_handler() -> Json<ConfigResponse> {
    let config = crate::config::AppConfig::from_env();
    Json(ConfigResponse {
        scan: ScanConfigResponse {
            default_timeout_ms: config.scan.default_timeout_ms,
            default_concurrency: config.scan.default_concurrency,
            max_concurrency_tcp: config.scan.max_concurrency_tcp,
            max_concurrency_syn: config.scan.max_concurrency_syn,
            max_concurrency_udp: config.scan.max_concurrency_udp,
            default_port_range: config.scan.default_port_range,
        },
        server: ServerConfigResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            cors_enabled: config.server.cors_enabled,
        },
    })
}

/// Classify an IP address or hostname.
async fn classify_handler(Path(target): Path<String>) -> Result<Json<IpClassifyResponse>> {
    let ip = crate::modules::parser::resolve_target(&target)?;
    let classification = network::classify_ip(&ip);
    let is_private = network::is_private_ip(&ip);

    Ok(Json(IpClassifyResponse {
        ip: ip.to_string(),
        classification: format!("{classification}"),
        is_private,
    }))
}

/// Search the vulnerability database by service name.
async fn vuln_search_handler(Query(params): Query<VulnSearchQuery>) -> Json<Vec<VulnSearchResult>> {
    let results = vuln_db::search_by_service(&params.q);
    let response: Vec<VulnSearchResult> = results
        .into_iter()
        .map(|(port, vuln)| VulnSearchResult {
            port,
            name: vuln.name,
            risk: format!("{}", vuln.risk),
            description: vuln.description,
            remediation: vuln_db::get_remediation(port),
        })
        .collect();
    Json(response)
}

/// Look up vulnerabilities for a specific port.
async fn vuln_port_handler(Path(port): Path<u16>) -> Json<serde_json::Value> {
    match vuln_db::get_vuln_for_port(port) {
        Some(vuln) => Json(serde_json::json!({
            "port": port,
            "name": vuln.name,
            "risk": format!("{}", vuln.risk),
            "description": vuln.description,
            "remediation": vuln_db::get_remediation(port)
        })),
        None => Json(serde_json::json!({
            "port": port,
            "name": null,
            "risk": "None",
            "description": "No known vulnerabilities for this port",
            "remediation": null
        })),
    }
}

/// Validate a filename to prevent path traversal attacks.
fn validate_filename(filename: &str) -> Result<()> {
    if !std::path::Path::new(filename)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        || filename.contains("..")
        || filename.contains('/')
        || filename.contains('\\')
    {
        return Err(crate::AppError::Validation(
            "Invalid filename: must be a .json file without path traversal characters".to_string(),
        ));
    }
    Ok(())
}

/// Count the number of JSON scan files in the scans directory.
fn count_scan_files() -> usize {
    fs::read_dir("scans")
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_str().is_some_and(|n| n.ends_with(".json")))
                .count()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_request_deserialization() {
        let json = r#"{"target":"localhost","range":"1-100","scan_type":"tcp"}"#;
        let req: ScanRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.target, "localhost");
        assert_eq!(req.range, "1-100");
        assert_eq!(req.scan_type, "tcp");
        assert_eq!(req.timeout, 1000);
    }

    #[tokio::test]
    async fn test_scan_request_defaults() {
        let json = r#"{"target":"test","range":"80"}"#;
        let req: ScanRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.scan_type, "");
        assert_eq!(req.timeout, 1000);
        assert_eq!(req.concurrency, 500);
    }

    #[tokio::test]
    async fn test_index_handler() {
        let response = index_handler().await;
        assert!(response.0.contains("<!DOCTYPE html>"));
        assert!(response.0.contains("SecOps Scanner"));
    }

    #[tokio::test]
    async fn test_health_handler() {
        let Json(response) = health_handler().await;
        assert_eq!(response["status"], "healthy");
        assert!(response["version"].is_string());
    }

    #[tokio::test]
    async fn test_stats_handler() {
        let Json(response) = stats_handler().await;
        assert_eq!(response.status, "operational");
        assert!(!response.version.is_empty());
        assert!(response.vuln_db_entries > 0);
        assert!(response.vuln_critical > 0);
    }

    #[tokio::test]
    async fn test_config_handler() {
        let Json(response) = config_handler().await;
        assert_eq!(response.scan.default_timeout_ms, 1000);
        assert!(response.scan.max_concurrency_tcp > 0);
        assert!(!response.server.version.is_empty());
    }

    #[tokio::test]
    async fn test_classify_handler_localhost() {
        let result = classify_handler(Path("127.0.0.1".to_string())).await;
        assert!(result.is_ok());
        let Json(resp) = result.unwrap();
        assert_eq!(resp.classification, "Loopback");
        assert!(resp.is_private);
    }

    #[tokio::test]
    async fn test_classify_handler_public() {
        let result = classify_handler(Path("8.8.8.8".to_string())).await;
        assert!(result.is_ok());
        let Json(resp) = result.unwrap();
        assert_eq!(resp.classification, "Public");
        assert!(!resp.is_private);
    }

    #[tokio::test]
    async fn test_vuln_search_handler() {
        let params = VulnSearchQuery {
            q: "SSH".to_string(),
        };
        let Json(results) = vuln_search_handler(Query(params)).await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.port == 22));
    }

    #[tokio::test]
    async fn test_vuln_port_handler_known() {
        let Json(resp) = vuln_port_handler(Path(23)).await;
        assert_eq!(resp["risk"], "Critical");
        assert!(resp["name"].is_string());
    }

    #[tokio::test]
    async fn test_vuln_port_handler_unknown() {
        let Json(resp) = vuln_port_handler(Path(12345)).await;
        assert_eq!(resp["risk"], "None");
    }

    #[test]
    fn test_validate_filename_valid() {
        assert!(validate_filename("scan_localhost_123.json").is_ok());
    }

    #[test]
    fn test_validate_filename_path_traversal() {
        assert!(validate_filename("../etc/passwd").is_err());
        assert!(validate_filename("..\\etc\\passwd").is_err());
        assert!(validate_filename("scan.txt").is_err());
    }

    #[test]
    fn test_validate_filename_no_extension() {
        assert!(validate_filename("noextension").is_err());
    }

    #[test]
    fn test_count_scan_files() {
        let count = count_scan_files();
        assert!(count < 100000);
    }
}
