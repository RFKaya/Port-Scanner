use axum::{
    routing::{get, post},
    Json, Router,
    response::Html,
};
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
