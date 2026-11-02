# MediaFlow Proxy Light ⚡️ — AIOStreams edition

A trimmed fork of [mediaflow-proxy-light](https://github.com/mhdzumair/mediaflow-proxy-light)
(the Rust reimplementation of [MediaFlow Proxy](https://github.com/mhdzumair/mediaflow-proxy))
that keeps only what [AIOStreams](https://github.com/Viren070/AIOStreams) uses when it is set to
proxy Stremio streams through MediaFlow, plus a password-protected usage dashboard.

## What's in it

| Method | Path | Used by |
|---|---|---|
| `GET` | `/proxy/ip` | AIOStreams — public IP the debrid links are bound to |
| `POST` | `/generate_urls` | AIOStreams — batch URL generation (encrypted `/_token_…` or plain) |
| `GET/HEAD` | `/proxy/stream`, `/proxy/stream/<filename>` | The Stremio player, via the URLs above (Range / seeking supported) |
| `GET` | `/health` | Health checks |
| `GET` | `/` | Usage dashboard (sign-in page without a session) |

Auth is unchanged from MediaFlow: `?api_password=…`, an encrypted `?token=…`, or a
`/_token_…/` path prefix. `/generate_urls` reads `api_password` from its JSON body.

Everything else from upstream is gone: HLS and DASH/MPD proxying, ClearKey DRM, the
video extractors, Telegram, Acestream, Xtream Codes, EPG proxy, `/proxy/forward`,
transcoding, Redis, the iOS/Android FFI, `/metrics`, `/generate_url`, `/base64/*`, and the
web tools (URL generator, speed test, playlist builder). Addons that call MediaFlow
themselves with your URL (e.g. WebStreamr) need those — use upstream if you rely on them.

## Dashboard

Open the server root (`/`) and sign in with the API password. The server answers with
an `HttpOnly`, `SameSite=Strict` session cookie (an HMAC of the password, never the
password itself) and checks it on the page and on every JSON feed
(`/dashboard/stats`, `/dashboard/history`). Without an API password configured the
dashboard stays locked. Changing the password signs every browser out.

## Run with Docker

```bash
docker run -d \
  -p 8888:8888 \
  -e APP__SERVER__HOST=0.0.0.0 \
  -e APP__AUTH__API_PASSWORD=your-secure-password \
  ghcr.io/buildermaxi/mediaflow-proxy-light:latest
```

In AIOStreams, set the proxy to **MediaFlow Proxy** with this server's URL and the same
password.

## Run natively (Raspberry Pi, any Linux)

Every merge to `main` also publishes the Linux binaries (x86_64 and arm64) as a GitHub
release. On a 64-bit Linux with systemd and glibc 2.36+ (Debian 12, Raspberry Pi OS
Bookworm, Ubuntu 22.10 or newer), this installs the latest one as a sandboxed systemd
service, listening on port 8888:

```bash
curl -fsSL https://github.com/buildermaxi/mediaflow-proxy-light/releases/latest/download/install.sh | sudo bash
```

A random API password is generated and printed on first install; pass
`MEDIAFLOW_API_PASSWORD=…` after `sudo` to choose it instead. On a Raspberry Pi the OS
must be the **64-bit** Raspberry Pi OS: check that `dpkg --print-architecture` prints
`arm64`.

- **Configuration:** `/etc/mediaflow-proxy-light/env` (the `APP__*` variables below), then
  `sudo systemctl restart mediaflow-proxy-light`
- **Logs:** `journalctl -u mediaflow-proxy-light -f`
- **Update:** run the same command again; it only restarts the service when the binary
  changed. Set `MEDIAFLOW_VERSION=<release tag>` after `sudo` to install a given release.
- **Uninstall:** `sudo systemctl disable --now mediaflow-proxy-light && sudo rm -r
  /usr/local/bin/mediaflow-proxy-light /etc/systemd/system/mediaflow-proxy-light.service
  /etc/mediaflow-proxy-light`

## Configuration

Loaded from environment variables → TOML file (`CONFIG_PATH`, see
[`config-example.toml`](config-example.toml)) → built-in defaults.
The flat `API_PASSWORD`, `HOST`, `PORT`, `WORKERS`, `PROXY_URL` and `ALL_PROXY` variables
of the Python proxy are accepted too.

```bash
# Server
APP__SERVER__HOST=0.0.0.0
APP__SERVER__PORT=8888
APP__SERVER__WORKERS=4

# Auth (also unlocks the dashboard)
APP__AUTH__API_PASSWORD=your-secure-password

# Upstream HTTP client
APP__PROXY__CONNECT_TIMEOUT=30
APP__PROXY__FOLLOW_REDIRECTS=true
APP__PROXY__PROXY_URL="socks5://user:pass@proxy:1080"   # optional upstream proxy
APP__PROXY__ALL_PROXY=false
APP__PROXY__REQUEST_TIMEOUT_FACTOR=8
APP__PROXY__MAX_CONCURRENT_PER_HOST=10
APP__PROXY__POOL_IDLE_TIMEOUT=90
APP__PROXY__POOL_MAX_IDLE_PER_HOST=100
APP__PROXY__TRANSPORT_ROUTES='{"all://*.cdn.example.com": {"proxy": true, "proxy_url": "socks5://proxy:1080"}}'

# Public IP returned by /proxy/ip. When unset, each call looks it up through the
# upstream proxy settings above, so behind WARP / SOCKS it's the proxy's exit IP.
APP__FORWARD__PUBLIC_IP=203.0.113.10

# Logging
APP__LOG_LEVEL=info
```

## Build

```bash
cargo build --release
```

TLS uses rustls by default; `--no-default-features --features tls-native` switches to the
system OpenSSL.

```bash
cargo test
cargo fmt
cargo clippy --all-targets -- -D warnings
```

## License

[MIT License](LICENSE)
