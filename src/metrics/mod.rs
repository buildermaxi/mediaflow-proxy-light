//! Lightweight request/traffic metrics using atomic counters.
//!
//! `AppMetrics` is created once and stored in actix-web `Data<AppMetrics>`.
//! Bytes served, open streams and media response outcomes are recorded once,
//! centrally, by the [`traffic`] middleware; `GET /dashboard/*` feeds the web
//! dashboard.

pub mod clients;
pub mod dashboard;
pub mod history;
pub mod system;
pub mod traffic;
pub mod upstream;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use actix_web::http::StatusCode;
use serde::Serialize;

use clients::{ClientTable, ClientView};
use history::{Checkpoint, History, HistoryView};
use upstream::UpstreamStats;

// ---------------------------------------------------------------------------
// Stream kinds
// ---------------------------------------------------------------------------

/// What a media request serves; drives the per-type breakdowns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    Direct,
    Other,
}

impl StreamKind {
    pub const ALL: [StreamKind; 2] = [Self::Direct, Self::Other];
    pub const COUNT: usize = Self::ALL.len();

    /// Classify a request path; `None` for non-media routes (UI, health,
    /// dashboard), which are neither metered nor counted as usage.
    pub fn from_path(path: &str) -> Option<Self> {
        const PREFIXES: &[(&str, StreamKind)] = &[
            ("/proxy/stream", StreamKind::Direct),
            ("/proxy/", StreamKind::Other),
        ];
        PREFIXES
            .iter()
            .find(|(prefix, _)| path.starts_with(prefix))
            .map(|(_, kind)| *kind)
    }

    fn index(self) -> usize {
        self as usize
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct AppMetrics {
    /// Response bodies currently being streamed to clients.
    pub active_connections: AtomicU64,
    pub bytes_out: AtomicU64,

    /// Unix timestamp (seconds) when the process started.
    pub start_time: AtomicU64,

    bytes_by_kind: [AtomicU64; StreamKind::COUNT],
    open_by_kind: [AtomicU64; StreamKind::COUNT],
    /// Media responses, and how many of them failed (status >= 400).
    media_responses: AtomicU64,
    media_failures: AtomicU64,

    clients: Mutex<ClientTable>,
    history: Mutex<History>,
    /// Per-upstream-host health, fed by `StreamManager`.
    pub upstream: Arc<UpstreamStats>,
}

/// Cumulative counters at one instant; history samples are deltas of these.
#[derive(Debug, Clone, Copy, Default)]
pub struct Totals {
    pub bytes_by_kind: [u64; StreamKind::COUNT],
    pub responses: u64,
    pub failures: u64,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl AppMetrics {
    pub fn new() -> Arc<Self> {
        let m = Arc::new(Self::default());
        m.start_time.store(unix_now(), Ordering::Relaxed);
        m
    }

    pub fn add_bytes(&self, kind: StreamKind, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
        self.bytes_by_kind[kind.index()].fetch_add(n, Ordering::Relaxed);
    }

    pub fn uptime_secs(&self) -> u64 {
        unix_now().saturating_sub(self.start_time.load(Ordering::Relaxed))
    }

    pub fn record_media_response(&self, status: StatusCode) {
        self.media_responses.fetch_add(1, Ordering::Relaxed);
        if status.is_client_error() || status.is_server_error() {
            self.media_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Register a response body starting to stream to `client`, returning
    /// that client's byte counter. Must be paired with [`AppMetrics::stream_closed`].
    pub fn stream_opened(
        &self,
        client: IpAddr,
        kind: StreamKind,
        player: &'static str,
    ) -> Arc<AtomicU64> {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.open_by_kind[kind.index()].fetch_add(1, Ordering::Relaxed);
        locked(&self.clients).open(client, kind, player, unix_now())
    }

    pub fn stream_closed(&self, client: IpAddr, kind: StreamKind) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        self.open_by_kind[kind.index()].fetch_sub(1, Ordering::Relaxed);
        locked(&self.clients).close(client, unix_now());
    }

    pub fn open_streams(&self, kind: StreamKind) -> u64 {
        self.open_by_kind[kind.index()].load(Ordering::Relaxed)
    }

    pub fn bytes_served(&self, kind: StreamKind) -> u64 {
        self.bytes_by_kind[kind.index()].load(Ordering::Relaxed)
    }

    /// Distinct client IPs that are streaming now or were within the idle window.
    pub fn active_clients(&self) -> usize {
        locked(&self.clients).active_count(unix_now())
    }

    /// Active clients with masked IPs, busiest first.
    pub fn clients(&self) -> Vec<ClientView> {
        locked(&self.clients).snapshot(unix_now())
    }

    pub fn totals(&self) -> Totals {
        Totals {
            bytes_by_kind: StreamKind::ALL.map(|k| self.bytes_served(k)),
            responses: self.media_responses.load(Ordering::Relaxed),
            failures: self.media_failures.load(Ordering::Relaxed),
        }
    }

    /// Append a per-minute history sample and age the upstream stats.
    /// Called by [`history::spawn_sampler`].
    pub fn sample_minute(&self) {
        let checkpoint = Checkpoint {
            at: Instant::now(),
            unix_secs: unix_now(),
            totals: self.totals(),
            users: self.active_clients(),
            rss_bytes: system::resident_memory_bytes(),
        };
        locked(&self.history).record(checkpoint);
        self.upstream.decay();
    }

    pub fn history(&self) -> HistoryView {
        locked(&self.history).view()
    }

    /// `(responses, failures)` over roughly the last five minutes.
    pub fn recent_outcomes(&self) -> (u64, u64) {
        let now = self.totals();
        locked(&self.history).recent_outcomes(&now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_media_paths() {
        assert_eq!(
            StreamKind::from_path("/proxy/stream/movie.mkv"),
            Some(StreamKind::Direct)
        );
        assert_eq!(StreamKind::from_path("/live/u/p/123.ts"), None);
        assert_eq!(StreamKind::from_path("/proxy/ip"), Some(StreamKind::Other));
        assert_eq!(StreamKind::from_path("/dashboard/stats"), None);
        assert_eq!(StreamKind::from_path("/"), None);
    }
}
