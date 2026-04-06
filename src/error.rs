use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

// Central error handling for the application
#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON Error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Target Resolution Error: Could not resolve target '{0}'")]
    Resolution(String),

    #[error("Scanner Error: {0}")]
    Scanner(String),

    #[error("Internal Server Error")]
    Internal,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// Enable Axum to use AppError as a response
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Io(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::Json(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            AppError::Resolution(target) => (
                StatusCode::BAD_REQUEST,
                format!("Could not resolve target '{target}'"),
            ),
            AppError::Scanner(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        let body = axum::Json(ErrorResponse {
            error: error_message,
        });

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
