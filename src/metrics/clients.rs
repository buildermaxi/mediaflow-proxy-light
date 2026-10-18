//! Per-client activity: the "active users" estimate and the clients table.
//!
//! Keyed by client IP; each client shows the file it last opened.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::Serialize;

/// A client stays "active" this long (seconds) after its last stream closed.
/// Covers the idle gap between a player's successive range requests.
const IDLE_WINDOW_SECS: u64 = 60;

/// Rows returned to the dashboard; the estimate itself counts every client.
const MAX_LISTED: usize = 50;

pub const UNKNOWN_PLAYER: &str = "Unknown";

/// User-Agent fragment → player name. First match wins, so specific apps come
/// before the generic engines/browsers they embed.
const PLAYERS: &[(&str, &str)] = &[
    ("tivimate", "TiviMate"),
    ("ott navigator", "OTT Navigator"),
    ("ottnavigator", "OTT Navigator"),
    ("smarters", "IPTV Smarters"),
    ("kodi", "Kodi"),
    ("stremio", "Stremio"),
    ("jellyfin", "Jellyfin"),
    ("emby", "Emby"),
    ("plex", "Plex"),
    ("infuse", "Infuse"),
    ("vlc", "VLC"),
    ("mpv", "mpv"),
    ("lavf", "FFmpeg"),
    ("exoplayer", "ExoPlayer"),
    ("media3", "ExoPlayer"),
    ("applecoremedia", "Apple player"),
    ("dalvik", "Android app"),
    ("okhttp", "Android app"),
    ("curl", "curl"),
    ("wget", "wget"),
    ("mozilla", "Browser"),
];

pub fn player_from_user_agent(user_agent: &str) -> &'static str {
    let ua = user_agent.as_bytes();
    PLAYERS
        .iter()
        .find(|(needle, _)| {
            ua.windows(needle.len())
                .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
        })
        .map_or(UNKNOWN_PLAYER, |(_, name)| name)
}

#[derive(Debug, Default)]
pub(super) struct ClientTable {
    by_ip: HashMap<IpAddr, ClientActivity>,
    last_prune: u64,
    next_id: u32,
}

#[derive(Debug)]
struct ClientActivity {
    id: u32,
    open_streams: u32,
    first_seen: u64,
    last_seen: u64,
    player: &'static str,
    /// File name of the last stream opened, as sent (percent-encoded).
    title: Option<Box<str>>,
    /// Bytes served to this client; bumped lock-free by its open streams.
    bytes: Arc<AtomicU64>,
}

#[derive(Debug, Serialize)]
pub struct ClientView {
    /// Opaque and stable while the client stays active, so the page can
    /// derive per-client rates from successive `bytes` samples.
    pub id: u32,
    pub ip: String,
    pub player: &'static str,
    pub title: Option<String>,
    pub streaming: bool,
    pub bytes: u64,
    pub since_secs: u64,
}

impl ClientTable {
    pub(super) fn open(
        &mut self,
        ip: IpAddr,
        player: &'static str,
        title: Option<&str>,
        now: u64,
    ) -> Arc<AtomicU64> {
        if now.saturating_sub(self.last_prune) >= IDLE_WINDOW_SECS {
            self.prune(now);
        }
        let next_id = &mut self.next_id;
        let client = self.by_ip.entry(ip).or_insert_with(|| {
            *next_id = next_id.wrapping_add(1);
            ClientActivity {
                id: *next_id,
                open_streams: 0,
                first_seen: now,
                last_seen: now,
                player,
                title: None,
                bytes: Arc::default(),
            }
        });
        client.open_streams += 1;
        client.last_seen = now;
        if player != UNKNOWN_PLAYER {
            client.player = player;
        }
        // A player's successive range requests repeat the same name: only
        // allocate when it changes.
        if let Some(title) = title.filter(|t| client.title.as_deref() != Some(*t)) {
            client.title = Some(title.into());
        }
        Arc::clone(&client.bytes)
    }

    pub(super) fn close(&mut self, ip: IpAddr, now: u64) {
        if let Some(client) = self.by_ip.get_mut(&ip) {
            client.open_streams = client.open_streams.saturating_sub(1);
            client.last_seen = now;
        }
    }

    pub(super) fn active_count(&mut self, now: u64) -> usize {
        self.prune(now);
        self.by_ip.len()
    }

    pub(super) fn snapshot(&mut self, now: u64) -> Vec<ClientView> {
        self.prune(now);
        let mut views: Vec<ClientView> = self
            .by_ip
            .iter()
            .map(|(ip, c)| ClientView {
                id: c.id,
                ip: ip.to_string(),
                player: c.player,
                title: c.title.as_deref().map(|t| {
                    urlencoding::decode(t).map_or_else(|_| t.to_owned(), |d| d.into_owned())
                }),
                streaming: c.open_streams > 0,
                bytes: c.bytes.load(Ordering::Relaxed),
                since_secs: now.saturating_sub(c.first_seen),
            })
            .collect();
        views.sort_by_key(|c| (Reverse(c.streaming), Reverse(c.bytes)));
        views.truncate(MAX_LISTED);
        views
    }

    fn prune(&mut self, now: u64) {
        self.by_ip.retain(|_, c| {
            c.open_streams > 0 || now.saturating_sub(c.last_seen) < IDLE_WINDOW_SECS
        });
        self.last_prune = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_players_case_insensitively() {
        assert_eq!(
            player_from_user_agent("TiviMate/5.1.6 (Android 12)"),
            "TiviMate"
        );
        assert_eq!(
            player_from_user_agent("Kodi/21.0 (Linux; Android 11)"),
            "Kodi"
        );
        assert_eq!(player_from_user_agent("VLC/3.0.20 LibVLC/3.0.20"), "VLC");
        assert_eq!(
            player_from_user_agent("Mozilla/5.0 (X11; Linux) Firefox/130"),
            "Browser"
        );
        assert_eq!(player_from_user_agent(""), UNKNOWN_PLAYER);
    }

    #[test]
    fn counts_clients_until_idle_window_expires() {
        let mut table = ClientTable::default();
        let (a, b): (IpAddr, IpAddr) = (
            "203.0.113.1".parse().unwrap(),
            "198.51.100.1".parse().unwrap(),
        );

        table.open(a, "Kodi", Some("First.Movie.mkv"), 1_000);
        table.open(a, UNKNOWN_PLAYER, Some("Second%20Movie.2160p.mkv"), 1_000);
        let bytes_b = table.open(b, "VLC", None, 1_000);
        bytes_b.fetch_add(500, Ordering::Relaxed);
        table.close(a, 1_010);
        table.close(a, 1_010);
        assert_eq!(table.active_count(1_030), 2);

        let rows = table.snapshot(1_030);
        assert_eq!(
            (rows[0].ip.as_str(), rows[0].bytes, rows[0].streaming),
            ("198.51.100.1", 500, true)
        );
        assert_eq!(rows[0].title, None);
        assert_eq!(
            (rows[1].player, rows[1].title.as_deref(), rows[1].streaming),
            ("Kodi", Some("Second Movie.2160p.mkv"), false)
        );

        // `a` idled out; `b` still has an open stream.
        assert_eq!(table.active_count(1_010 + IDLE_WINDOW_SECS), 1);
    }

    #[test]
    fn keeps_the_last_named_file() {
        let mut table = ClientTable::default();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();

        table.open(ip, "Stremio", Some("Movie%20One.mkv"), 1_000);
        // `/proxy/ip`, or a stream URL without a name, keeps the last one.
        table.open(ip, "Stremio", None, 1_001);
        assert_eq!(
            table.snapshot(1_002)[0].title.as_deref(),
            Some("Movie One.mkv")
        );

        // Not UTF-8 once decoded: shown as sent.
        table.open(ip, "Stremio", Some("bad%FF.mkv"), 1_003);
        assert_eq!(
            table.snapshot(1_004)[0].title.as_deref(),
            Some("bad%FF.mkv")
        );
    }
}
