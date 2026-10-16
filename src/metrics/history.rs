//! Rolling 24 h of per-minute samples behind the dashboard's history chart,
//! peaks and failure rate. Fixed size: about 52 B × 1440 ≈ 75 KB when full.
//! In memory only, so history starts over when the process restarts.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::{AppMetrics, StreamKind, Totals};

const RETENTION_MINUTES: usize = 24 * 60;
/// Minute samples are merged into at most this many chart buckets (5 min each
/// when the full 24 h is retained, 1 min while history is short).
const MAX_BUCKETS: usize = 288;
/// Failure-rate window, in completed minutes (plus the current partial one).
const RECENT_MINUTES: usize = 5;

/// Start the once-a-minute sampler; it runs for the life of the process.
pub fn spawn_sampler(metrics: Arc<AppMetrics>) {
    actix_web::rt::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // The first tick fires immediately and only sets the baseline.
            tick.tick().await;
            metrics.sample_minute();
        }
    });
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Checkpoint {
    pub at: Instant,
    pub unix_secs: u64,
    pub totals: Totals,
    pub users: usize,
    pub rss_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct MinuteSample {
    /// Unix seconds when the sample was taken (end of its minute).
    end: u32,
    /// Actual length of the sample; ~60 unless the process was suspended.
    secs: u16,
    users: u16,
    kib_by_kind: [u32; StreamKind::COUNT],
    responses: u32,
    failures: u32,
    rss_kib: u32,
}

#[derive(Debug, Default)]
pub(super) struct History {
    samples: VecDeque<MinuteSample>,
    last: Option<Checkpoint>,
}

#[derive(Debug, Serialize)]
pub struct HistoryView {
    pub bucket_secs: u64,
    /// Bucket start times (unix seconds).
    pub t: Vec<u64>,
    /// Seconds of data in each bucket — divide bytes by this for a rate, so
    /// the in-progress bucket isn't understated.
    pub secs: Vec<u64>,
    /// Bytes served per bucket, only for kinds that had traffic.
    pub series: Vec<KindSeries>,
    pub peaks: Peaks,
}

#[derive(Debug, Serialize)]
pub struct KindSeries {
    pub kind: StreamKind,
    pub bytes: Vec<u64>,
}

/// Highest per-minute values over the retained window.
#[derive(Debug, Default, Serialize)]
pub struct Peaks {
    pub bytes_per_sec: u64,
    pub users: u16,
    pub rss_bytes: u64,
}

fn saturate_u32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

fn saturate_u16(v: u64) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

impl History {
    pub(super) fn record(&mut self, now: Checkpoint) {
        let Some(prev) = self.last.replace(now) else {
            return;
        };
        let delta = |cur: u64, old: u64| cur.saturating_sub(old);
        self.samples.push_back(MinuteSample {
            end: saturate_u32(now.unix_secs),
            secs: saturate_u16(now.at.duration_since(prev.at).as_secs().max(1)),
            users: saturate_u16(now.users as u64),
            kib_by_kind: std::array::from_fn(|k| {
                saturate_u32(
                    delta(now.totals.bytes_by_kind[k], prev.totals.bytes_by_kind[k]) / 1024,
                )
            }),
            responses: saturate_u32(delta(now.totals.responses, prev.totals.responses)),
            failures: saturate_u32(delta(now.totals.failures, prev.totals.failures)),
            rss_kib: saturate_u32(now.rss_bytes.unwrap_or(0) / 1024),
        });
        if self.samples.len() > RETENTION_MINUTES {
            self.samples.pop_front();
        }
    }

    pub(super) fn recent_outcomes(&self, now: &Totals) -> (u64, u64) {
        let base = self.last.map(|cp| cp.totals).unwrap_or_default();
        let mut responses = now.responses.saturating_sub(base.responses);
        let mut failures = now.failures.saturating_sub(base.failures);
        for s in self.samples.iter().rev().take(RECENT_MINUTES) {
            responses += u64::from(s.responses);
            failures += u64::from(s.failures);
        }
        (responses, failures)
    }

    pub(super) fn view(&self) -> HistoryView {
        let bucket_secs = 60 * self.samples.len().div_ceil(MAX_BUCKETS).max(1) as u64;
        let mut buckets: Vec<(u64, u64, [u64; StreamKind::COUNT])> = Vec::new();
        let mut peaks = Peaks::default();
        for s in &self.samples {
            let midpoint = u64::from(s.end).saturating_sub(u64::from(s.secs) / 2);
            let start = midpoint / bucket_secs * bucket_secs;
            if buckets.last().map(|b| b.0) != Some(start) {
                buckets.push((start, 0, [0; StreamKind::COUNT]));
            }
            let total: u64 = s.kib_by_kind.iter().map(|&kib| u64::from(kib) * 1024).sum();
            if let Some((_, secs, bytes)) = buckets.last_mut() {
                *secs += u64::from(s.secs);
                for (acc, kib) in bytes.iter_mut().zip(s.kib_by_kind) {
                    *acc += u64::from(kib) * 1024;
                }
            }
            peaks.bytes_per_sec = peaks.bytes_per_sec.max(total / u64::from(s.secs));
            peaks.users = peaks.users.max(s.users);
            peaks.rss_bytes = peaks.rss_bytes.max(u64::from(s.rss_kib) * 1024);
        }

        let series = StreamKind::ALL
            .iter()
            .enumerate()
            .filter(|(k, _)| buckets.iter().any(|b| b.2[*k] > 0))
            .map(|(k, &kind)| KindSeries {
                kind,
                bytes: buckets.iter().map(|b| b.2[k]).collect(),
            })
            .collect();

        HistoryView {
            bucket_secs,
            t: buckets.iter().map(|b| b.0).collect(),
            secs: buckets.iter().map(|b| b.1).collect(),
            series,
            peaks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(
        at: Instant,
        minute: u64,
        hls_bytes: u64,
        responses: u64,
        failures: u64,
    ) -> Checkpoint {
        let mut totals = Totals {
            responses,
            failures,
            ..Totals::default()
        };
        totals.bytes_by_kind[StreamKind::Hls.index()] = hls_bytes;
        Checkpoint {
            at: at + Duration::from_secs(minute * 60),
            unix_secs: 1_800_000_000 + minute * 60,
            totals,
            users: minute as usize,
            rss_bytes: Some(40 << 20),
        }
    }

    #[test]
    fn buckets_deltas_and_tracks_peaks() {
        let t0 = Instant::now();
        let mut history = History::default();
        history.record(checkpoint(t0, 0, 0, 0, 0));
        history.record(checkpoint(t0, 1, 6_144_000, 100, 1));
        history.record(checkpoint(t0, 2, 6_144_000, 150, 1));

        let view = history.view();
        assert_eq!(view.series.len(), 1);
        assert_eq!(view.series[0].kind, StreamKind::Hls);
        assert_eq!(view.series[0].bytes.iter().sum::<u64>(), 6_144_000);
        assert_eq!(view.secs.iter().sum::<u64>(), 120);
        assert_eq!(view.peaks.bytes_per_sec, 102_400);
        assert_eq!(view.peaks.users, 2);
        assert_eq!(view.peaks.rss_bytes, 40 << 20);

        // Two completed minutes plus the in-progress one since the last tick.
        let now = checkpoint(t0, 2, 6_144_000, 160, 3).totals;
        assert_eq!(history.recent_outcomes(&now), (160, 3));
    }
}
