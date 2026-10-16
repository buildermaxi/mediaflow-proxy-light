//! Lightweight request/traffic metrics using atomic counters.
//!
//! `AppMetrics` is created once and stored in actix-web `Data<AppMetrics>`.
//! Handlers bump the per-endpoint request counters; bytes served and open
//! streams are recorded once, centrally, by the [`traffic`] middleware.
//! `GET /metrics` returns the counters as JSON and `GET /dashboard/stats`
//! feeds the web dashboard.

pub mod dashboard;
pub mod traffic;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{web, HttpResponse};
use serde::Serialize;

/// A client stays "active" this long (seconds) after its last stream closed.
/// Covers the idle gap between HLS/DASH segment fetches.
const CLIENT_IDLE_WINDOW_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct AppMetrics {
    pub total_requests: AtomicU64,
    /// Response bodies currently being streamed to clients.
    pub active_connections: AtomicU64,
    pub bytes_out: AtomicU64,

    // Per-endpoint counters
    pub proxy_stream_requests: AtomicU64,
    pub hls_requests: AtomicU64,
    pub mpd_requests: AtomicU64,
    pub telegram_requests: AtomicU64,
    pub extractor_requests: AtomicU64,

    /// Unix timestamp (seconds) when the process started.
    pub start_time: AtomicU64,

    clients: Mutex<ClientTable>,
}

/// Per-IP activity, used to estimate how many people are using the proxy.
/// Bounded: entries idle for longer than [`CLIENT_IDLE_WINDOW_SECS`] are pruned.
#[derive(Debug, Default)]
struct ClientTable {
    by_ip: HashMap<IpAddr, ClientActivity>,
    last_prune: u64,
}

#[derive(Debug, Default)]
struct ClientActivity {
    open_streams: u32,
    last_seen: u64,
}

impl ClientTable {
    fn prune(&mut self, now: u64) {
        self.by_ip.retain(|_, c| {
            c.open_streams > 0 || now.saturating_sub(c.last_seen) < CLIENT_IDLE_WINDOW_SECS
        });
        self.last_prune = now;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl AppMetrics {
    pub fn new() -> Arc<Self> {
        let m = Arc::new(Self::default());
        m.start_time.store(unix_now(), Ordering::Relaxed);
        m
    }

    pub fn inc_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    pub fn uptime_secs(&self) -> u64 {
        unix_now().saturating_sub(self.start_time.load(Ordering::Relaxed))
    }

    /// Register a response body starting to stream to `client`.
    /// Must be paired with [`AppMetrics::stream_closed`].
    pub fn stream_opened(&self, client: IpAddr) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        let now = unix_now();
        let mut clients = self.clients();
        if now.saturating_sub(clients.last_prune) >= CLIENT_IDLE_WINDOW_SECS {
            clients.prune(now);
        }
        let entry = clients.by_ip.entry(client).or_default();
        entry.open_streams += 1;
        entry.last_seen = now;
    }

    pub fn stream_closed(&self, client: IpAddr) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        if let Some(entry) = self.clients().by_ip.get_mut(&client) {
            entry.open_streams = entry.open_streams.saturating_sub(1);
            entry.last_seen = unix_now();
        }
    }

    /// Distinct client IPs that are streaming now or were within the idle window.
    pub fn active_clients(&self) -> usize {
        let mut clients = self.clients();
        clients.prune(unix_now());
        clients.by_ip.len()
    }

    fn clients(&self) -> MutexGuard<'_, ClientTable> {
        self.clients.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// ---------------------------------------------------------------------------
// JSON response shape
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct MetricsResponse {
    uptime_seconds: u64,
    total_requests: u64,
    active_connections: u64,
    bytes_out: u64,
    bytes_out_human: String,
    proxy_stream_requests: u64,
    hls_requests: u64,
    mpd_requests: u64,
    telegram_requests: u64,
    extractor_requests: u64,
}

fn human_bytes(b: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut val = b as f64;
    let mut i = 0;
    while val >= 1024.0 && i < UNITS.len() - 1 {
        val /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{val:.0} {}", UNITS[i])
    } else {
        format!("{val:.2} {}", UNITS[i])
    }
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

pub async fn metrics_handler(metrics: web::Data<Arc<AppMetrics>>) -> HttpResponse {
    let bytes_out = metrics.bytes_out.load(Ordering::Relaxed);

    HttpResponse::Ok().json(MetricsResponse {
        uptime_seconds: metrics.uptime_secs(),
        total_requests: metrics.total_requests.load(Ordering::Relaxed),
        active_connections: metrics.active_connections.load(Ordering::Relaxed),
        bytes_out,
        bytes_out_human: human_bytes(bytes_out),
        proxy_stream_requests: metrics.proxy_stream_requests.load(Ordering::Relaxed),
        hls_requests: metrics.hls_requests.load(Ordering::Relaxed),
        mpd_requests: metrics.mpd_requests.load(Ordering::Relaxed),
        telegram_requests: metrics.telegram_requests.load(Ordering::Relaxed),
        extractor_requests: metrics.extractor_requests.load(Ordering::Relaxed),
    })
}
