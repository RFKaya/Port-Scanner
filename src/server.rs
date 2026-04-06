use crate::persistence::models::ScanResult;
use crate::Result;
use axum::{
    extract::Path,
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        Html,
    },
    routing::{delete, get, post},
    Json, Router,
};
use futures::StreamExt;
use serde::Deserialize;
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

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

pub async fn start_server(port: u16) {
    let app = Router::new()
        // API and Static Routes
        .route("/", get(index_handler))
        .route("/api/scan", post(scan_handler))
        .route("/api/scan/stream", post(scan_stream_handler))
        .route("/api/history", get(list_history_handler))
        .route("/api/history/:filename", get(get_history_handler))
        .route("/api/history/:filename", delete(delete_history_handler))
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("Server starting on http://{addr}");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {addr}: {e}");
            return;
        }
    };

    // Start serving the app
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Server error: {e}");
    }
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../public/index.html"))
}

async fn scan_handler(Json(payload): Json<ScanRequest>) -> Result<Json<ScanResult>> {
    let syn = payload.scan_type == "syn";
    let udp = payload.scan_type == "udp";

    // Perform scan and return results as JSON
    let result = crate::run_port_scan_logic(
        payload.target,
        payload.range,
        syn,
        udp,
        payload.timeout,
        payload.concurrency,
    )
    .await?;

    // Save scan to disk as JSON
    result.save_to_file()?;

    Ok(Json(result))
}

async fn scan_stream_handler(
    Json(payload): Json<ScanRequest>,
) -> Sse<impl futures::Stream<Item = std::result::Result<Event, Infallible>>> {
    let syn = payload.scan_type == "syn";
    let udp = payload.scan_type == "udp";

    // Backup scan parameters (for background saving)
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

    // Start a background task to complete the scan and save it to disk
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

    // Stream results using SSE (Server-Sent Events)
    Sse::new(event_stream)
}

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
    // Sort by timestamp in filename in descending order (newest first)
    history.sort_by(|a, b| b.cmp(a));
    Json(history)
}

async fn get_history_handler(Path(filename): Path<String>) -> Result<Json<ScanResult>> {
    // Security check to prevent path traversal
    if !std::path::Path::new(&filename)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        || filename.contains("..")
        || filename.contains('/')
        || filename.contains('\\')
    {
        return Err(crate::AppError::Scanner("Invalid filename".to_string()));
    }

    let path = format!("scans/{filename}");
    let content = fs::read_to_string(path)?;
    let result = serde_json::from_str::<ScanResult>(&content)?;
    Ok(Json(result))
}

async fn delete_history_handler(Path(filename): Path<String>) -> Result<StatusCode> {
    if !std::path::Path::new(&filename)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        || filename.contains("..")
        || filename.contains('/')
        || filename.contains('\\')
    {
        return Err(crate::AppError::Scanner("Invalid filename".to_string()));
    }

    let path = format!("scans/{filename}");
    fs::remove_file(path)?;
    Ok(StatusCode::OK)
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
        assert_eq!(req.timeout, 1000); // default
    }

    #[tokio::test]
    async fn test_index_handler() {
        let response = index_handler().await;
        // Html wrapper should contain the start of the index.html
        assert!(response.0.contains("<!DOCTYPE html>"));
        assert!(response.0.contains("SecOps Scanner"));
    }
}
