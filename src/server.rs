use axum::{
    routing::{get, post, delete},
    Json, Router,
    response::{Html, sse::{Event, Sse}},
    extract::Path,
    http::StatusCode,
};
use futures::StreamExt;
use std::convert::Infallible;
use serde::Deserialize;
use std::net::SocketAddr;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::run_port_scan_logic;
use crate::models::ScanResult;
use tower_http::cors::CorsLayer;

#[derive(Deserialize)]
pub struct ScanRequest {
    target: String,
    range: String,
    #[serde(default)]
    scan_type: String, // "tcp", "syn", "udp"
    #[serde(default = "default_timeout")]
    timeout: u64,
}

fn default_timeout() -> u64 { 1000 }

pub async fn start_server(port: u16) {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/scan", post(scan_handler))
        .route("/api/scan/stream", post(scan_stream_handler))
        .route("/api/history", get(list_history_handler))
        .route("/api/history/:filename", get(get_history_handler))
        .route("/api/history/:filename", delete(delete_history_handler))
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("Server starting on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../public/index.html"))
}

async fn scan_handler(Json(payload): Json<ScanRequest>) -> Json<ScanResult> {
    let syn = payload.scan_type == "syn";
    let udp = payload.scan_type == "udp";
    
    let target_name = payload.target.clone();
    
    let result = run_port_scan_logic(
        payload.target,
        payload.range,
        syn,
        udp,
        payload.timeout,
    ).await;
    
    // Klasörün varlığından emin ol
    let _ = fs::create_dir_all("scans");
    
    // Benzersiz bir dosya ismi oluştur (hedef_isim + timestamp)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    let target_safe = target_name.replace(|c: char| !c.is_alphanumeric(), "_");
    let filename = format!("scans/scan_{}_{}.json", target_safe, timestamp);
    
    // Taramayı JSON olarak diske kaydet
    if let Ok(json_str) = serde_json::to_string_pretty(&result) {
        let _ = fs::write(&filename, json_str);
    }
    
    Json(result)
}

async fn scan_stream_handler(Json(payload): Json<ScanRequest>) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let syn = payload.scan_type == "syn";
    let udp = payload.scan_type == "udp";
    
    // Tarama parametrelerini yedekleyelim (arka plan kaydı için)
    let target_save = payload.target.clone();
    let range_save = payload.range.clone();
    let timeout_save = payload.timeout;
    
    let stream = crate::run_port_scan_logic_stream(
        payload.target,
        payload.range,
        syn,
        udp,
        payload.timeout,
    ).await;

    // Arka planda taramayı tamamlayıp diske kaydedecek bir görev başlatalım
    tokio::spawn(async move {
        let result = crate::run_port_scan_logic(
            target_save,
            range_save,
            syn,
            udp,
            timeout_save,
        ).await;

        let _ = fs::create_dir_all("scans");
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let target_safe = result.target.replace(|c: char| !c.is_alphanumeric(), "_");
        let filename = format!("scans/scan_{}_{}.json", target_safe, timestamp);
        
        if let Ok(json_str) = serde_json::to_string_pretty(&result) {
            let _ = fs::write(&filename, json_str);
        }
    });

    let event_stream = stream.map(|res| {
        let json = serde_json::to_string(&res).unwrap_or_default();
        Ok(Event::default().data(json))
    });

    Sse::new(event_stream)
}

async fn list_history_handler() -> Json<Vec<String>> {
    let mut history = Vec::new();
    if let Ok(entries) = fs::read_dir("scans") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name.ends_with(".json") {
                    history.push(name);
                }
            }
        }
    }
    // Dosya ismindeki timestamp'e göre azalan sırada (en yeni en üstte)
    history.sort_by(|a, b| b.cmp(a));
    Json(history)
}

async fn get_history_handler(Path(filename): Path<String>) -> Result<Json<ScanResult>, StatusCode> {
    // Güvenlik kontrolü
    if !filename.ends_with(".json") || filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let path = format!("scans/{}", filename);
    if let Ok(content) = fs::read_to_string(path) {
        if let Ok(result) = serde_json::from_str::<ScanResult>(&content) {
            return Ok(Json(result));
        }
    }
    Err(StatusCode::NOT_FOUND)
}

async fn delete_history_handler(Path(filename): Path<String>) -> StatusCode {
    if !filename.ends_with(".json") || filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return StatusCode::BAD_REQUEST;
    }
    
    let path = format!("scans/{}", filename);
    if fs::remove_file(path).is_ok() {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}
