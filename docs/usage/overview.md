# Usage: Overview & Endpoints

The proxy listens on port `8888` by default. All endpoints accept an `api_password` query parameter when `APP__AUTH__API_PASSWORD` is set.

## Stream proxy

| Method | Path | Description |
|---|---|---|
| `GET/HEAD` | `/proxy/stream` | Generic HTTP(S) stream proxy |
| `GET/HEAD` | `/proxy/stream/<filename>` | Stream proxy with filename hint for players |

**Parameters:** `d=<url>`, `api_password`, `h_<Name>=<value>` (custom headers).

## HLS

| Method | Path | Description |
|---|---|---|
| `GET/HEAD` | `/proxy/hls/manifest.m3u8` | HLS master/media manifest proxy |
| `GET/HEAD` | `/proxy/hls/segment.<ext>` | HLS segment proxy |

**Parameters:** `d=<m3u8_url>`, `api_password`, `h_<Name>=<value>`.

## DASH / MPD

| Method | Path | Description |
|---|---|---|
| `GET/HEAD` | `/proxy/mpd/manifest.m3u8` | DASH → HLS master manifest |
| `GET/HEAD` | `/proxy/mpd/playlist.m3u8` | DASH → HLS media playlist (per profile) |
| `GET/HEAD` | `/proxy/mpd/segment.mp4` | DASH segment (fMP4) |
| `GET/HEAD` | `/proxy/mpd/segment.ts` | DASH segment (MPEG-TS remux) |
| `GET/HEAD` | `/proxy/mpd/init.mp4` | DASH init segment |

## EPG proxy

| Method | Path | Description |
|---|---|---|
| `GET/HEAD` | `/proxy/epg` | Fetch and cache XMLTV/EPG data |

See [EPG proxy](epg-proxy.md) for full details.

## Transcoding

| Method | Path | Description |
|---|---|---|
| `GET/HEAD` | `/proxy/transcode/playlist.m3u8` | HLS VOD playlist for generic stream transcode |
| `GET/HEAD` | `/proxy/transcode/init.mp4` | fMP4 init segment for generic transcode |
| `GET/HEAD` | `/proxy/transcode/segment.m4s` | fMP4 media segment for generic transcode |

Add `&transcode=true` to any `/proxy/stream` request to trigger transcoding. Optional `&start=<seconds>` for seeking.

## Video extractor

| Method | Path | Description |
|---|---|---|
| `GET/HEAD` | `/extractor/video` | Extract stream URL from a video host |
| `GET/HEAD` | `/extractor/video.<ext>` | Same, with extension hint for players |

See [Video extractor](extractor.md) for the full host list and usage.

## Xtream Codes

| Path | Description |
|---|---|
| `/player_api.php` | XC player API |
| `/xmltv.php` | XC EPG/XMLTV endpoint |
| `/get.php` | M3U playlist export |
| `/<username>/<password>/<stream_id>.<ext>` | Short stream URL |

See [Xtream Codes proxy](xtream.md).

## Acestream

| Path | Description |
|---|---|
| `/proxy/acestream/manifest.m3u8` | HLS manifest for Acestream content |
| `/proxy/acestream/stream` | MPEG-TS stream |
| `/proxy/acestream/status` | Session status |

## Telegram

| Path | Description |
|---|---|
| `/proxy/telegram/stream` | Stream Telegram media |
| `/proxy/telegram/stream/<filename>` | Stream with filename hint for players |
| `/proxy/telegram/info` | Media metadata (size, MIME type, filename) |
| `/proxy/telegram/status` | Session connection status |

**Identification parameters** (use one combination per request):

| Params | Mode |
|---|---|
| `d=<t.me URL>` | Public or private `t.me` link |
| `chat_id` + `message_id` | Recommended — fresh reference, never expires |
| `chat_id` + `document_id` | Scans recent chat history |
| `chat_id` + `file_id` | Decodes file_id to find document in chat |
| `file_id` + `file_size` | Standalone Bot-API file_id (file_size required) |

See [Telegram setup & usage](telegram.md) for full details and examples.

Transcoded variants:

| Path | Description |
|---|---|
| `/proxy/telegram/transcode/playlist.m3u8` | HLS VOD playlist for Telegram transcode |
| `/proxy/telegram/transcode/init.mp4` | fMP4 init segment |
| `/proxy/telegram/transcode/segment.m4s` | fMP4 media segment |

## Forward proxy

| Method | Path | Description |
|---|---|---|
| `GET/POST/PUT/PATCH/DELETE/…` | `/proxy/forward` | Transparent relay — forwards any request via MediaFlow's IP |

**Parameters:** `d=<url>`, `api_password`, `h_<Name>=<value>` (outbound headers), `r_<Name>=<value>` (response header overrides).

Use `{mediaflow_ip}` anywhere in `d` or the request body and MediaFlow substitutes its own public IP before forwarding — useful for debrid `ip=` binding.

See [Forward proxy](forward.md) for full details.

## Utilities

| Method | Path | Description |
|---|---|---|
| `GET` | `/proxy/ip` | Public IP of the proxy server |
| `POST` | `/generate_url` | Generate signed/encrypted proxy URL |
| `POST` | `/base64/encode` | Base64-encode a URL |
| `POST` | `/base64/decode` | Decode a base64 URL |
| `GET` | `/base64/check` | Check if a string is base64-encoded |
| `GET` | `/health` | Health check (`{"status":"ok"}`) |
| `GET` | `/metrics` | Prometheus-style request metrics |
| `GET` | `/dashboard` | Live dashboard UI: memory, CPU, users, bandwidth by stream type, upstream health (API password required) |
| `GET` | `/dashboard/stats` | Live JSON feed for the dashboard (`Authorization: Bearer <api_password>`) |
| `GET` | `/dashboard/history` | Last 24 h of bandwidth, peaks and failures, kept in memory (`Authorization: Bearer <api_password>`) |
| `GET` | `/playlist/builder` | M3U playlist builder UI |
| `GET` | `/speedtest` | Speed test UI |

## Quick examples

```bash
# Generic stream
mpv "http://localhost:8888/proxy/stream?d=https://example.com/video.mp4&api_password=secret"

# HLS with custom Referer header
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://example.com/live.m3u8&h_Referer=https://example.com&api_password=secret"

# EPG proxy (for Channels DVR)
curl "http://localhost:8888/proxy/epg?d=http://provider.com/epg.xml&api_password=secret"

# Extract stream from a video host
curl "http://localhost:8888/extractor/video?host=vidoza&d=https://vidoza.net/abc123&api_password=secret"

# Get proxy public IP (for Debrid service allowlisting)
curl "http://localhost:8888/proxy/ip"
```
