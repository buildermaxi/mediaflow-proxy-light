use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::Path;
use tracing::warn;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

// ── ProxyConfig defaults ────────────────────────────────────────────────────
//
// These apply to omitted TOML keys so older config files keep working.
fn default_request_timeout_factor() -> u64 {
    8
}
fn default_max_concurrent_per_host() -> usize {
    10
}
fn default_pool_idle_timeout() -> u64 {
    90
}
fn default_pool_max_idle_per_host() -> usize {
    100
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    /// TCP handshake timeout (seconds) for a new upstream connection.
    pub connect_timeout: u64,

    /// Whether reqwest should follow 3xx redirects (addon playback links
    /// usually redirect to the debrid download).
    pub follow_redirects: bool,

    // ── Tunables (all have sensible defaults) ─────────────────────────────
    /// Multiplier applied to `connect_timeout` to derive the full request
    /// timeout (covers pool-wait + connect + TLS + response headers).
    ///
    /// Default: `8` → request timeout = connect_timeout × 8.
    #[serde(default = "default_request_timeout_factor")]
    pub request_timeout_factor: u64,

    /// Maximum concurrent in-flight upstream requests per origin host.
    /// Matches aiohttp's `limit_per_host=10` default; set to 0 to disable.
    /// Capping here forces HTTP/1.1 keep-alive reuse for bursty traffic
    /// and dramatically reduces per-request latency.
    ///
    /// Default: `10`.
    #[serde(default = "default_max_concurrent_per_host")]
    pub max_concurrent_per_host: usize,

    /// Seconds an idle upstream connection is kept in the pool before eviction.
    ///
    /// Default: `90`.
    #[serde(default = "default_pool_idle_timeout")]
    pub pool_idle_timeout: u64,

    /// Maximum idle upstream connections retained per host.
    ///
    /// Default: `100`.
    #[serde(default = "default_pool_max_idle_per_host")]
    pub pool_max_idle_per_host: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    /// Required: the server refuses to start without one. It authenticates
    /// `/proxy/ip`, the dashboard, and is the key the stream tokens are
    /// sealed with by the client.
    pub api_password: String,
    /// Longest lifetime, in seconds, a stream token may have left when it is
    /// used: tokens without an expiry, or expiring further away, are
    /// refused. `0` lifts the limit.
    ///
    /// Default: `172800` (48 hours).
    #[serde(default = "default_token_ttl")]
    pub token_ttl: u64,
}

fn default_token_ttl() -> u64 {
    172_800
}

// ---------------------------------------------------------------------------
// Public IP config
// ---------------------------------------------------------------------------

/// The `[forward]` section. Only `public_ip` is left (the `/proxy/forward`
/// relay is gone); the section name is kept so existing
/// `APP__FORWARD__PUBLIC_IP` settings keep working.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ForwardConfig {
    /// MediaFlow's own public IP, returned by `GET /proxy/ip`. When unset,
    /// each call looks it up (IPv4 only).
    #[serde(default)]
    pub public_ip: Option<String>,
}

// ---------------------------------------------------------------------------
// Root config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub proxy: ProxyConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub forward: ForwardConfig,
    /// Log filter directive (e.g. "debug", "info", "mediaflow_proxy_light=debug,info").
    /// Overrides the RUST_LOG env var when set.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info,actix_http::h1=off".to_string()
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut builder = config::Config::builder()
            // Server
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8888)?
            .set_default("server.workers", 4)?
            // Proxy
            .set_default("proxy.connect_timeout", 30)?
            .set_default("proxy.follow_redirects", true)?
            // Auth: no default password (see `main`, which refuses to start
            // with an empty one).
            .set_default("auth.api_password", "")?;

        if let Ok(config_path) = std::env::var("CONFIG_PATH") {
            let path = Path::new(&config_path);
            if path.exists() {
                builder = builder.add_source(config::File::with_name(&config_path));
            } else {
                warn!("Config file not found at {}", config_path);
            }
        }

        builder = builder.add_source(
            config::Environment::with_prefix("APP")
                .separator("__")
                .try_parsing(true),
        );

        let mut config: Config = builder.build()?.try_deserialize()?;
        // `try_parsing` turns numeric-looking values into numbers ("00123456" →
        // 123456, "1e5" → 100000): the password must stay the exact string the
        // client derives its token key from.
        if let Ok(raw) = std::env::var("APP__AUTH__API_PASSWORD") {
            config.auth.api_password = raw;
        }
        Ok(config)
    }

    /// Checks what the server must not run with, normalising along the way.
    /// Returns the warnings to log, or the reason to refuse to start.
    pub fn validate(&mut self) -> Result<Vec<String>, String> {
        let mut warnings = Vec::new();

        // No password, no server: it authenticates `/proxy/ip` and the
        // dashboard, and it is the key stream tokens are sealed with.
        let password = self.auth.api_password.as_str();
        if password.is_empty() {
            return Err(
                "APP__AUTH__API_PASSWORD is not set. Set it (the same value as AIO \
                 Reborn's MEDIAFLOW_API_PASSWORD) and restart."
                    .to_string(),
            );
        }
        if ["your-password", "changeme"].contains(&password) {
            return Err(format!(
                "APP__AUTH__API_PASSWORD is the example value \"{password}\": set a secret one."
            ));
        }
        if password.chars().count() < 16 {
            warnings.push(
                "APP__AUTH__API_PASSWORD is shorter than 16 characters: a captured playback \
                 link would allow guessing it offline."
                    .to_string(),
            );
        }

        // `/proxy/ip` only answers an IPv4 (debrid services are IPv4-only).
        match self.forward.public_ip.as_deref().map(str::trim) {
            None => {}
            Some("") => self.forward.public_ip = None,
            Some(ip) => match ip.parse::<Ipv4Addr>() {
                Ok(ip) => self.forward.public_ip = Some(ip.to_string()),
                Err(_) => {
                    return Err(format!(
                        "APP__FORWARD__PUBLIC_IP must be an IPv4 address, got \"{ip}\"."
                    ))
                }
            },
        }

        for legacy in ["API_PASSWORD", "PROXY_URL", "ALL_PROXY"] {
            if std::env::var_os(legacy).is_some() {
                warnings.push(format!(
                    "{legacy} is no longer read: only the APP__* variables are (and upstream \
                     proxies are gone)."
                ));
            }
        }
        Ok(warnings)
    }
}
