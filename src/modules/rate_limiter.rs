//! Rate Limiter Module
//!
//! Token-bucket algorithm for controlling scan throughput.

use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::sleep;

/// Configuration for the rate limiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_rate: u32,
    pub burst_size: u32,
    pub adaptive: bool,
    pub backoff_factor: f64,
    pub recovery_factor: f64,
    pub min_rate: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_rate: 1000,
            burst_size: 100,
            adaptive: true,
            backoff_factor: 0.5,
            recovery_factor: 1.1,
            min_rate: 10,
        }
    }
}

impl fmt::Display for RateLimitConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Rate: {}/s, Burst: {}, Adaptive: {}",
            self.max_rate, self.burst_size, self.adaptive
        )
    }
}

/// Token-bucket rate limiter for scan throughput control.
pub struct TokenBucket {
    config: RateLimitConfig,
    tokens: Arc<Semaphore>,
    ops_count: Arc<AtomicUsize>,
    timeout_count: Arc<AtomicUsize>,
    created_at: Instant,
    effective_rate: Arc<AtomicU64>,
}

impl TokenBucket {
    /// Create a new token bucket with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        let burst = config.burst_size as usize;
        let effective_rate = config.max_rate as u64;
        let bucket = Self {
            config: config.clone(),
            tokens: Arc::new(Semaphore::new(burst)),
            ops_count: Arc::new(AtomicUsize::new(0)),
            timeout_count: Arc::new(AtomicUsize::new(0)),
            created_at: Instant::now(),
            effective_rate: Arc::new(AtomicU64::new(effective_rate)),
        };
        bucket.start_refill_task();
        bucket
    }

    /// Create a rate limiter with sensible defaults for a given rate.
    pub fn with_rate(max_rate: u32) -> Self {
        Self::new(RateLimitConfig {
            max_rate,
            burst_size: (max_rate / 10).max(10),
            ..Default::default()
        })
    }

    /// Acquire a token, waiting if none are available.
    pub async fn acquire(&self) {
        if let Ok(p) = self.tokens.acquire().await {
            p.forget();
        }
        self.ops_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Report a timeout for adaptive rate adjustment.
    pub fn report_timeout(&self) {
        self.timeout_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current effective rate.
    pub fn current_rate(&self) -> u64 {
        self.effective_rate.load(Ordering::Relaxed)
    }

    /// Get total operations performed.
    pub fn total_operations(&self) -> usize {
        self.ops_count.load(Ordering::Relaxed)
    }

    /// Get total timeouts reported.
    pub fn total_timeouts(&self) -> usize {
        self.timeout_count.load(Ordering::Relaxed)
    }

    /// Get elapsed time since creation.
    pub fn elapsed(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Calculate actual operations-per-second rate.
    pub fn actual_rate(&self) -> f64 {
        let elapsed = self.created_at.elapsed().as_secs_f64();
        if elapsed < 0.001 {
            return 0.0;
        }
        self.ops_count.load(Ordering::Relaxed) as f64 / elapsed
    }

    /// Start background token refill task.
    fn start_refill_task(&self) {
        let tokens = Arc::clone(&self.tokens);
        let effective_rate = Arc::clone(&self.effective_rate);
        let timeout_count = Arc::clone(&self.timeout_count);
        let config = self.config.clone();
        let burst_size = config.burst_size as usize;

        tokio::spawn(async move {
            let base_interval_ms = 1000.0 / config.max_rate as f64;
            let mut current_interval_ms = base_interval_ms;

            loop {
                sleep(Duration::from_micros((current_interval_ms * 1000.0) as u64)).await;

                if tokens.available_permits() < burst_size {
                    tokens.add_permits(1);
                }

                if config.adaptive {
                    let timeouts = timeout_count.load(Ordering::Relaxed);
                    if timeouts > 0 {
                        current_interval_ms /= config.backoff_factor;
                        let min_interval = 1000.0 / config.min_rate as f64;
                        current_interval_ms = current_interval_ms.min(min_interval);
                        timeout_count.store(0, Ordering::Relaxed);
                    } else {
                        current_interval_ms /= config.recovery_factor;
                        current_interval_ms = current_interval_ms.max(base_interval_ms);
                    }
                    let new_rate = (1000.0 / current_interval_ms) as u64;
                    effective_rate.store(new_rate.max(config.min_rate as u64), Ordering::Relaxed);
                }
            }
        });
    }
}

impl fmt::Display for TokenBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TokenBucket(rate={}/s, ops={}, timeouts={}, actual={:.1}/s)",
            self.current_rate(),
            self.total_operations(),
            self.total_timeouts(),
            self.actual_rate()
        )
    }
}

/// Fixed-window rate counter for monitoring throughput (no enforcement).
#[derive(Debug)]
pub struct RateCounter {
    window: Duration,
    timestamps: std::sync::Mutex<Vec<Instant>>,
}

impl RateCounter {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            timestamps: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Record an operation.
    pub fn record(&self) {
        let now = Instant::now();
        let mut ts = self.timestamps.lock().unwrap();
        ts.push(now);
        let cutoff = now - self.window;
        ts.retain(|t| *t > cutoff);
    }

    /// Get current rate within the window.
    pub fn rate(&self) -> f64 {
        let now = Instant::now();
        let ts = self.timestamps.lock().unwrap();
        let cutoff = now - self.window;
        let count = ts.iter().filter(|t| **t > cutoff).count();
        count as f64 / self.window.as_secs_f64()
    }

    /// Get count of operations in the current window.
    pub fn count_in_window(&self) -> usize {
        let now = Instant::now();
        let ts = self.timestamps.lock().unwrap();
        let cutoff = now - self.window;
        ts.iter().filter(|t| **t > cutoff).count()
    }
}

impl fmt::Display for RateCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RateCounter(window={:?}, rate={:.1}/s)",
            self.window,
            self.rate()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_rate, 1000);
        assert_eq!(config.burst_size, 100);
        assert!(config.adaptive);
    }

    #[test]
    fn test_config_display() {
        let display = format!("{}", RateLimitConfig::default());
        assert!(display.contains("1000/s"));
    }

    #[tokio::test]
    async fn test_token_bucket_creation() {
        let bucket = TokenBucket::with_rate(100);
        assert_eq!(bucket.total_operations(), 0);
        assert_eq!(bucket.total_timeouts(), 0);
    }

    #[tokio::test]
    async fn test_token_bucket_acquire() {
        let bucket = TokenBucket::with_rate(1000);
        bucket.acquire().await;
        bucket.acquire().await;
        assert_eq!(bucket.total_operations(), 2);
    }

    #[tokio::test]
    async fn test_token_bucket_timeout_report() {
        let bucket = TokenBucket::with_rate(100);
        bucket.report_timeout();
        bucket.report_timeout();
        assert_eq!(bucket.total_timeouts(), 2);
    }

    #[tokio::test]
    async fn test_token_bucket_display() {
        let bucket = TokenBucket::with_rate(500);
        bucket.acquire().await;
        let display = format!("{bucket}");
        assert!(display.contains("ops=1"));
    }

    #[test]
    fn test_rate_counter_creation() {
        let counter = RateCounter::new(Duration::from_secs(1));
        assert_eq!(counter.count_in_window(), 0);
    }

    #[test]
    fn test_rate_counter_record() {
        let counter = RateCounter::new(Duration::from_secs(10));
        counter.record();
        counter.record();
        counter.record();
        assert_eq!(counter.count_in_window(), 3);
    }

    #[test]
    fn test_rate_counter_display() {
        let counter = RateCounter::new(Duration::from_secs(1));
        let display = format!("{counter}");
        assert!(display.contains("RateCounter"));
    }
}
