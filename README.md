# MediaFlow Proxy Light ⚡️ — AIO Reborn edition

A trimmed fork of [mediaflow-proxy-light](https://github.com/mhdzumair/mediaflow-proxy-light)
(the Rust reimplementation of [MediaFlow Proxy](https://github.com/mhdzumair/mediaflow-proxy))
that keeps only what [AIO Reborn](https://github.com/buildermaxi/aio-reborn) needs to send every
Stremio stream through one machine — so the debrid service only ever sees its IP — plus a
password-protected usage dashboard.

## What's in it

| Method | Path | Used by |
|---|---|---|
| `GET/HEAD` | `/_token_<token>/proxy/stream[/<filename>]` | The Stremio player, via URLs AIO Reborn builds (Range / seeking supported) |
| `GET` | `/proxy/ip?api_password=…` | AIO Reborn — the public IPv4 debrid links are bound to |
| `GET` | `/health` | Health checks |
| `GET` | `/` | Usage dashboard (sign-in page without a session) |

### Stream tokens

AIO Reborn mints the stream tokens itself, with the API password, and builds
`<public URL>/_token_<token>/proxy/stream/<filename>` URLs: the server only opens them. There
is no URL-generation route. A token is
`base64url-no-pad(version ‖ nonce[12] ‖ AES-256-GCM(json))`, with the key derived from the API
password by HKDF-SHA256 (see [`src/auth/encryption.rs`](src/auth/encryption.rs); the contract is
pinned by [`tests/aio_reborn_contract.rs`](tests/aio_reborn_contract.rs), which opens a token
minted by AIO Reborn's own code).

- A token that wasn't sealed with the API password, or was modified, is refused.
- It only works on the endpoint it was minted for (`/proxy/stream`).
- It must expire, at most `APP__AUTH__TOKEN_TTL` from now (48 hours by default), whatever
  lifetime the client asked for.
- Everything a stream needs is in the token: any query string added to a token URL is dropped.
- Every rejected token gets the same `401 {"error":"Invalid or expired token"}`.

The API password only opens `/proxy/ip` directly: streams can't be reached with
`?api_password=…&d=…`, and there is no `?token=…` form.

### Gone

From upstream: HLS and DASH/MPD proxying, ClearKey DRM, the video extractors, Telegram,
Acestream, Xtream Codes, EPG proxy, `/proxy/forward`, transcoding, Redis, the iOS/Android FFI,
`/metrics`, `/generate_url`, `/base64/*`, and the web tools. Since the AIO Reborn edition, also:
`/generate_urls`, unencrypted (`?d=…&h_*=…`) and base64 URLs, `?token=…`, token IP binding,
upstream proxies (`PROXY_URL`, `ALL_PROXY`, transport routes: the debrid service must see this
machine's IP), the flat `API_PASSWORD`/`HOST`/… variables of the Python proxy, the no-password
mode, and the OpenSSL (`tls-native`) build. AIOStreams needs some of these: keep a pre-AIO Reborn
release for it.

## Dashboard

Open the server root (`/`) and sign in with the API password. The server answers with
an `HttpOnly`, `SameSite=Strict` session cookie (an HMAC of the password, never the
password itself) and checks it on the page and on every JSON feed
(`/dashboard/stats`, `/dashboard/history`). The server refuses to start without an API
password. Changing the password signs every browser out.

## Run with Docker

```bash
docker run -d \
  -p 8888:8888 \
  -e APP__SERVER__HOST=0.0.0.0 \
  -e APP__AUTH__API_PASSWORD=your-secure-password \
  ghcr.io/buildermaxi/mediaflow-proxy-light:latest
```

In AIO Reborn, set `MEDIAFLOW_URL` to this server's public URL and `MEDIAFLOW_API_PASSWORD` to
the same password.

## Run natively (Raspberry Pi, any Linux)

Every merge to `main` also publishes the Linux binaries (x86_64 and arm64) as a GitHub
release. On a 64-bit Linux with systemd and glibc 2.36+ (Debian 12, Raspberry Pi OS
Bookworm, Ubuntu 22.10 or newer), this installs the latest one as a sandboxed systemd
service, listening on port 8888:

```bash
curl -fsSL https://github.com/buildermaxi/mediaflow-proxy-light/releases/latest/download/install.sh | sudo bash
```

A random API password is generated and printed on first install. On a Raspberry Pi the
OS must be the **64-bit** Raspberry Pi OS: check that `dpkg --print-architecture` prints
`arm64`.

- **Configuration:** `/etc/mediaflow-proxy-light/env`, then
  `sudo systemctl restart mediaflow-proxy-light`. It takes the `APP__*` variables below,
  one `VAR=value` per line: systemd doesn't allow comments at the end of a line, so leave
  out the `# …` notes. That's also where you change the API password.
- **Logs:** `journalctl -u mediaflow-proxy-light -f`
- **Update:** run the same command again; it only restarts the service when the binary
  changed. Set `MEDIAFLOW_VERSION=<release tag>` after `sudo` to install a given release.
- **Uninstall:** `sudo systemctl disable --now mediaflow-proxy-light && sudo rm -r
  /usr/local/bin/mediaflow-proxy-light /etc/systemd/system/mediaflow-proxy-light.service
  /etc/mediaflow-proxy-light && sudo systemctl daemon-reload`

## Configuration

Loaded from environment variables → TOML file (`CONFIG_PATH`, see
[`config-example.toml`](config-example.toml)) → built-in defaults. Only the `APP__*` variables
are read.

```bash
# Server
APP__SERVER__HOST=0.0.0.0
APP__SERVER__PORT=8888
APP__SERVER__WORKERS=4

# Auth — required: the server doesn't start without a password. Same value as
# AIO Reborn's MEDIAFLOW_API_PASSWORD; it also unlocks the dashboard.
APP__AUTH__API_PASSWORD=your-secure-password
APP__AUTH__TOKEN_TTL=172800   # longest lifetime a stream token may have left, in seconds (0 = no cap)

# Upstream HTTP client (always direct: proxy environment variables are ignored)
APP__PROXY__CONNECT_TIMEOUT=30
APP__PROXY__FOLLOW_REDIRECTS=true
APP__PROXY__REQUEST_TIMEOUT_FACTOR=8
APP__PROXY__MAX_CONCURRENT_PER_HOST=10
APP__PROXY__POOL_IDLE_TIMEOUT=90
APP__PROXY__POOL_MAX_IDLE_PER_HOST=100

# Public IP returned by /proxy/ip. When unset, each call looks it up (IPv4 only).
APP__FORWARD__PUBLIC_IP=203.0.113.10

# Logging
APP__LOG_LEVEL=info
```

## Build

```bash
cargo build --release
```

TLS uses rustls, with Mozilla's CA list built in.

```bash
cargo test
cargo fmt
cargo clippy --all-targets -- -D warnings
```

## License

[MIT License](LICENSE)
