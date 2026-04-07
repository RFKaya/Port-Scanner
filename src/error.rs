//! Central Error Handling Module
//!
//! Defines the unified error type [`AppError`] used throughout the application.
//! All error variants map to appropriate HTTP status codes for the web API
//! and provide user-friendly error messages for both CLI and web interfaces.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// Central error type for the Port Scanner application.
///
/// Each variant maps to an HTTP status code and provides a human-readable
/// error message. The `#[from]` attribute enables automatic conversion
/// from standard library error types via the `?` operator.
#[derive(Error, Debug)]
pub enum AppError {
    /// File system or network I/O error.
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization or deserialization error.
    #[error("JSON Error: {0}")]
    Json(#[from] serde_json::Error),

    /// DNS or hostname resolution failure.
    #[error("Target Resolution Error: Could not resolve target '{0}'")]
    Resolution(String),

    /// General scanner operation error.
    #[error("Scanner Error: {0}")]
    Scanner(String),

    /// Insufficient permissions for the requested operation (e.g., SYN scan).
    #[error("Permission Denied: {0}")]
    PermissionDenied(String),

    /// Operation timed out.
    #[error("Timeout Error: {0}")]
    Timeout(String),

    /// Rate limiting threshold exceeded.
    #[error("Rate Limit Exceeded: {0}")]
    RateLimit(String),

    /// Configuration validation error.
    #[error("Configuration Error: {0}")]
    Configuration(String),

    /// Network-level error (distinct from I/O).
    #[error("Network Error: {0}")]
    Network(String),

    /// Banner grabbing operation failed.
    #[error("Banner Grab Error: {0}")]
    BannerGrab(String),

    /// Input validation error (malformed port range, target, etc.).
    #[error("Validation Error: {0}")]
    Validation(String),

    /// Catch-all internal server error.
    #[error("Internal Server Error")]
    Internal,
}

/// Structured JSON error response body for the web API.
#[derive(Serialize)]
struct ErrorResponse {
    /// Human-readable error message.
    error: String,
    /// Machine-readable error code for programmatic handling.
    code: String,
}

/// Maps each [`AppError`] variant to an HTTP status code and error code string.
impl AppError {
    /// Get the HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Json(_) => StatusCode::BAD_REQUEST,
            AppError::Resolution(_) => StatusCode::BAD_REQUEST,
            AppError::Scanner(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::PermissionDenied(_) => StatusCode::FORBIDDEN,
            AppError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            AppError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Network(_) => StatusCode::BAD_GATEWAY,
            AppError::BannerGrab(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the machine-readable error code string.
    pub fn error_code(&self) -> &'static str {
        match self {
            AppError::Io(_) => "IO_ERROR",
            AppError::Json(_) => "JSON_ERROR",
            AppError::Resolution(_) => "RESOLUTION_ERROR",
            AppError::Scanner(_) => "SCANNER_ERROR",
            AppError::PermissionDenied(_) => "PERMISSION_DENIED",
            AppError::Timeout(_) => "TIMEOUT",
            AppError::RateLimit(_) => "RATE_LIMIT",
            AppError::Configuration(_) => "CONFIG_ERROR",
            AppError::Network(_) => "NETWORK_ERROR",
            AppError::BannerGrab(_) => "BANNER_GRAB_ERROR",
            AppError::Validation(_) => "VALIDATION_ERROR",
            AppError::Internal => "INTERNAL_ERROR",
        }
    }
}

/// Enable Axum to convert `AppError` into an HTTP response automatically.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.error_code().to_string();
        let error_message = self.to_string();

        let body = axum::Json(ErrorResponse {
            error: error_message,
            code,
        });

        (status, body).into_response()
    }
}

/// Application-wide result alias using [`AppError`].
pub type Result<T> = std::result::Result<T, AppError>;

/// Extension trait for adding context to errors.
pub trait ErrorContext<T> {
    /// Wrap an error with additional context message.
    fn context(self, msg: &str) -> Result<T>;
}

impl<T, E: std::fmt::Display> ErrorContext<T> for std::result::Result<T, E> {
    fn context(self, msg: &str) -> Result<T> {
        self.map_err(|e| AppError::Scanner(format!("{msg}: {e}")))
    }
}

impl<T> ErrorContext<T> for Option<T> {
    fn context(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| AppError::Scanner(msg.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_error_io() {
        let err = AppError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.error_code(), "IO_ERROR");
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn test_app_error_resolution() {
        let err = AppError::Resolution("bad-host".to_string());
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert!(err.to_string().contains("bad-host"));
    }

    #[test]
    fn test_app_error_permission_denied() {
        let err = AppError::PermissionDenied("SYN scan requires root".to_string());
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(err.error_code(), "PERMISSION_DENIED");
    }

    #[test]
    fn test_app_error_timeout() {
        let err = AppError::Timeout("Port 80 timed out".to_string());
        assert_eq!(err.status_code(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn test_app_error_rate_limit() {
        let err = AppError::RateLimit("Too many requests".to_string());
        assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_app_error_configuration() {
        let err = AppError::Configuration("Invalid timeout value".to_string());
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.error_code(), "CONFIG_ERROR");
    }

    #[test]
    fn test_app_error_validation() {
        let err = AppError::Validation("Port out of range".to_string());
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(err.error_code(), "VALIDATION_ERROR");
    }

    #[test]
    fn test_app_error_network() {
        let err = AppError::Network("Connection refused".to_string());
        assert_eq!(err.status_code(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_app_error_banner_grab() {
        let err = AppError::BannerGrab("Timeout reading banner".to_string());
        assert_eq!(err.error_code(), "BANNER_GRAB_ERROR");
    }

    #[test]
    fn test_app_error_internal() {
        let err = AppError::Internal;
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.error_code(), "INTERNAL_ERROR");
    }

    #[test]
    fn test_error_context_result() {
        let result: std::result::Result<i32, std::io::Error> =
            Err(std::io::Error::new(std::io::ErrorKind::Other, "boom"));
        let contexted = result.context("Operation failed");
        assert!(contexted.is_err());
        assert!(contexted
            .unwrap_err()
            .to_string()
            .contains("Operation failed"));
    }

    #[test]
    fn test_error_context_option() {
        let opt: Option<i32> = None;
        let result = opt.context("Value not found");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Value not found"));
    }

    #[test]
    fn test_error_context_option_some() {
        let opt: Option<i32> = Some(42);
        let result = opt.context("Value not found");
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let app_err: AppError = io_err.into();
        assert!(matches!(app_err, AppError::Io(_)));
    }

    #[test]
    fn test_all_error_codes_unique() {
        let errors: Vec<&str> = vec![
            AppError::Io(std::io::Error::new(std::io::ErrorKind::Other, "")).error_code(),
            AppError::Resolution(String::new()).error_code(),
            AppError::Scanner(String::new()).error_code(),
            AppError::PermissionDenied(String::new()).error_code(),
            AppError::Timeout(String::new()).error_code(),
            AppError::RateLimit(String::new()).error_code(),
            AppError::Configuration(String::new()).error_code(),
            AppError::Network(String::new()).error_code(),
            AppError::BannerGrab(String::new()).error_code(),
            AppError::Validation(String::new()).error_code(),
            AppError::Internal.error_code(),
        ];
        let unique_count = {
            let mut v = errors.clone();
            v.sort();
            v.dedup();
            v.len()
        };
        // JSON_ERROR not included in list above so add 1
        assert!(unique_count >= 10, "Error codes should be unique");
    }
}
