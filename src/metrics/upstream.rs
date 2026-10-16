//! Per-upstream-host health: traffic share, failure rate and time to first
//! byte, fed by `StreamManager`.
//!
//! Recent-weighted rather than cumulative: every minute all counters decay by
//! 1/8 (roughly an 8-minute window) and hosts that went quiet are dropped, so
//! the table answers "is this provider slow or failing *now*". Bounded to
//! [`MAX_HOSTS`] entries.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use super::locked;

const MAX_HOSTS: usize = 32;
/// Rows returned to the dashboard.
const MAX_LISTED: usize = 10;
/// Upper bounds (ms) of the time-to-first-byte histogram buckets; slower
/// responses land in the last one.
const TTFB_BUCKETS_MS: [u32; 12] = [
    50, 100, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 10_000,
];

/// Counts upstream body bytes for one host; a no-op when stats are disabled.
#[derive(Debug, Clone, Default)]
pub struct ByteTally(Option<Arc<AtomicU64>>);

impl ByteTally {
    pub fn add(&self, n: usize) {
        if let Some(counter) = &self.0 {
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Default)]
pub struct UpstreamStats {
    hosts: Mutex<HashMap<String, HostStats>>,
}

#[derive(Debug, Default)]
struct HostStats {
    requests: u64,
    failures: u64,
    ttfb: [u64; TTFB_BUCKETS_MS.len()],
    bytes: Arc<AtomicU64>,
}

#[derive(Debug, Serialize)]
pub struct HostView {
    pub host: String,
    /// Share of recent upstream bytes, 0–1.
    pub share: f64,
    /// Failed share of recent requests (transport errors and status >= 400), 0–1.
    pub failure_rate: f64,
    /// Bucket upper bound containing the 95th percentile; 10000 means ≥ 10 s.
    pub ttfb_p95_ms: Option<u32>,
}

/// `host` or `host:port` (non-default ports only — IPTV panels often use :8080).
fn host_of(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

/// Shrink a counter by 1/8, reaching zero even for small values.
fn decayed(v: u64) -> u64 {
    v.saturating_mul(7) / 8
}

impl UpstreamStats {
    /// Record a response whose headers arrived after `ttfb`.
    pub fn record_response(&self, url: &str, ttfb: Duration, failed: bool) -> ByteTally {
        let Some(host) = host_of(url) else {
            return ByteTally::default();
        };
        let ms = u32::try_from(ttfb.as_millis()).unwrap_or(u32::MAX);
        let bucket = TTFB_BUCKETS_MS
            .iter()
            .position(|&bound| ms <= bound)
            .unwrap_or(TTFB_BUCKETS_MS.len() - 1);

        let mut hosts = locked(&self.hosts);
        let stats = Self::entry(&mut hosts, host);
        stats.requests += 1;
        stats.failures += u64::from(failed);
        stats.ttfb[bucket] += 1;
        ByteTally(Some(Arc::clone(&stats.bytes)))
    }

    /// Record a request that got no response (connect error or timeout).
    pub fn record_unreachable(&self, url: &str) {
        if let Some(host) = host_of(url) {
            let mut hosts = locked(&self.hosts);
            let stats = Self::entry(&mut hosts, host);
            stats.requests += 1;
            stats.failures += 1;
        }
    }

    fn entry(hosts: &mut HashMap<String, HostStats>, host: String) -> &mut HostStats {
        if hosts.len() >= MAX_HOSTS && !hosts.contains_key(&host) {
            let quietest = hosts
                .iter()
                .min_by_key(|(_, s)| s.requests)
                .map(|(h, _)| h.clone());
            if let Some(quietest) = quietest {
                hosts.remove(&quietest);
            }
        }
        hosts.entry(host).or_default()
    }

    /// Age every counter by one step; called once a minute.
    pub fn decay(&self) {
        let mut hosts = locked(&self.hosts);
        for stats in hosts.values_mut() {
            stats.requests = decayed(stats.requests);
            stats.failures = decayed(stats.failures);
            stats.ttfb.iter_mut().for_each(|b| *b = decayed(*b));
            let bytes = stats.bytes.load(Ordering::Relaxed);
            stats
                .bytes
                .fetch_sub(bytes - decayed(bytes), Ordering::Relaxed);
        }
        hosts.retain(|_, s| s.requests > 0 || s.bytes.load(Ordering::Relaxed) > 0);
    }

    /// Recently busiest hosts first.
    pub fn snapshot(&self) -> Vec<HostView> {
        let hosts = locked(&self.hosts);
        let bytes: Vec<u64> = hosts
            .values()
            .map(|s| s.bytes.load(Ordering::Relaxed))
            .collect();
        let total_bytes = bytes.iter().sum::<u64>().max(1) as f64;
        let mut views: Vec<(u64, HostView)> = hosts
            .iter()
            .zip(bytes)
            .map(|((host, s), bytes)| {
                let view = HostView {
                    host: host.clone(),
                    share: bytes as f64 / total_bytes,
                    failure_rate: s.failures as f64 / s.requests.max(1) as f64,
                    ttfb_p95_ms: p95(&s.ttfb),
                };
                (bytes + s.requests, view)
            })
            .collect();
        views.sort_by_key(|(weight, _)| std::cmp::Reverse(*weight));
        views.into_iter().take(MAX_LISTED).map(|(_, v)| v).collect()
    }
}

fn p95(buckets: &[u64; TTFB_BUCKETS_MS.len()]) -> Option<u32> {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return None;
    }
    let target = total.saturating_mul(95).div_ceil(100);
    let mut seen = 0;
    buckets
        .iter()
        .zip(TTFB_BUCKETS_MS)
        .find(|(&count, _)| {
            seen += count;
            seen >= target
        })
        .map(|(_, bound)| bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_share_failures_and_p95_per_host() {
        let stats = UpstreamStats::default();
        for _ in 0..19 {
            stats
                .record_response("https://cdn.example/a.ts", Duration::from_millis(80), false)
                .add(1_000);
        }
        stats
            .record_response("https://cdn.example/b.ts", Duration::from_millis(900), true)
            .add(1_000);
        stats.record_unreachable("https://slow.example/live.m3u8");

        let rows = stats.snapshot();
        assert_eq!(rows[0].host, "cdn.example");
        assert_eq!(rows[1].host, "slow.example");
        assert_eq!(rows[0].share, 1.0);
        assert_eq!(rows[0].failure_rate, 0.05);
        assert_eq!(rows[0].ttfb_p95_ms, Some(100));
        assert_eq!((rows[1].failure_rate, rows[1].ttfb_p95_ms), (1.0, None));
    }

    #[test]
    fn decay_forgets_idle_hosts() {
        let stats = UpstreamStats::default();
        stats.record_unreachable("https://gone.example/");
        stats.decay();
        assert!(stats.snapshot().is_empty());
    }
}
