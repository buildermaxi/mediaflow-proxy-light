//! Backend for the web dashboard (`static/dashboard.html`).
//!
//! - `GET /dashboard`         — redirect to the dashboard page
//! - `GET /dashboard/stats`   — live snapshot, polled every couple of seconds
//! - `GET /dashboard/history` — last 24 h in 5-minute buckets, polled each minute
//!
//! Both feeds authenticate themselves with `Authorization: Bearer
//! <api_password>` — a header rather than `?api_password=` so the secret
//! doesn't land in the access log on every poll. They are refused outright
//! when no `api_password` is configured, so the dashboard is never public.
//!
//! Live rates (bandwidth, CPU, per-client speed) are not computed here: the
//! page derives them from successive cumulative counters.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use actix_web::{http::header, web, HttpRequest, HttpResponse};
use serde::Serialize;

use super::{clients::ClientView, system, upstream::HostView, AppMetrics, StreamKind};
use crate::config::Config;
use crate::error::{AppError, AppResult};

#[derive(Serialize)]
struct DashboardStats {
    uptime_secs: u64,
    /// Resident memory of this process; `null` on unsupported platforms.
    memory_rss_bytes: Option<u64>,
    /// Cumulative CPU time; `null` on unsupported platforms.
    cpu_time_ms: Option<u64>,
    cpu_cores: usize,
    active_clients: usize,
    active_streams: u64,
    bytes_out: u64,
    kinds: Vec<KindStats>,
    /// Media responses / failures over roughly the last five minutes.
    recent_responses: u64,
    recent_failures: u64,
    clients: Vec<ClientView>,
    upstreams: Vec<HostView>,
    services: Services,
}

#[derive(Serialize)]
struct KindStats {
    kind: StreamKind,
    bytes: u64,
    open_streams: u64,
}

/// Status of optional subsystems; a field is absent when its feature isn't compiled in.
#[derive(Default, Serialize)]
struct Services {
    #[serde(skip_serializing_if = "Option::is_none")]
    hls_prebuffer: Option<PrebufferStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    telegram: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acestream: Option<AcestreamStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transcode: Option<TranscodeStatus>,
}

#[derive(Serialize)]
struct PrebufferStatus {
    hits: u64,
    misses: u64,
}

#[derive(Serialize)]
struct AcestreamStatus {
    streams: u64,
}

#[derive(Serialize)]
struct TranscodeStatus {
    enabled: bool,
    encoder: &'static str,
    jobs: u64,
}

pub async fn dashboard_redirect_handler() -> HttpResponse {
    HttpResponse::Found()
        .insert_header((header::LOCATION, "/dashboard.html"))
        .finish()
}

pub async fn dashboard_stats_handler(
    req: HttpRequest,
    config: web::Data<Arc<Config>>,
    metrics: web::Data<Arc<AppMetrics>>,
) -> AppResult<HttpResponse> {
    authorize(&req, &config.auth.api_password)?;

    let (recent_responses, recent_failures) = metrics.recent_outcomes();
    let stats = DashboardStats {
        uptime_secs: metrics.uptime_secs(),
        memory_rss_bytes: system::resident_memory_bytes(),
        cpu_time_ms: system::cpu_time().map(|t| t.as_millis() as u64),
        cpu_cores: system::cpu_cores(),
        active_clients: metrics.active_clients(),
        active_streams: metrics.active_connections.load(Ordering::Relaxed),
        bytes_out: metrics.bytes_out.load(Ordering::Relaxed),
        kinds: StreamKind::ALL
            .iter()
            .map(|&kind| KindStats {
                kind,
                bytes: metrics.bytes_served(kind),
                open_streams: metrics.open_streams(kind),
            })
            .collect(),
        recent_responses,
        recent_failures,
        clients: metrics.clients(),
        upstreams: metrics.upstream.snapshot(),
        services: services(&config, &metrics).await,
    };
    Ok(no_store(stats))
}

pub async fn dashboard_history_handler(
    req: HttpRequest,
    config: web::Data<Arc<Config>>,
    metrics: web::Data<Arc<AppMetrics>>,
) -> AppResult<HttpResponse> {
    authorize(&req, &config.auth.api_password)?;
    Ok(no_store(metrics.history()))
}

fn no_store(body: impl Serialize) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(body)
}

// Every field is feature-gated, so with a minimal feature set nothing is used.
#[allow(unused_mut, unused_variables)]
async fn services(config: &Config, metrics: &AppMetrics) -> Services {
    let mut services = Services::default();
    #[cfg(feature = "hls")]
    {
        services.hls_prebuffer = Some(PrebufferStatus {
            hits: metrics.prebuffer_hits.load(Ordering::Relaxed),
            misses: metrics.prebuffer_misses.load(Ordering::Relaxed),
        });
    }
    #[cfg(feature = "telegram")]
    {
        services.telegram =
            Some(crate::telegram::handler::connection_status(&config.telegram).await);
    }
    #[cfg(feature = "acestream")]
    {
        services.acestream = Some(AcestreamStatus {
            streams: metrics.open_streams(StreamKind::Acestream),
        });
    }
    #[cfg(feature = "transcode")]
    {
        services.transcode = Some(TranscodeStatus {
            enabled: config.transcode.enabled,
            encoder: crate::transcode::hw_detect::cached_encoder(),
            jobs: metrics.open_streams(StreamKind::Transcode),
        });
    }
    services
}

fn authorize(req: &HttpRequest, api_password: &str) -> AppResult<()> {
    if api_password.is_empty() {
        return Err(AppError::Forbidden(
            "Dashboard is disabled: set APP__AUTH__API_PASSWORD to enable it".into(),
        ));
    }
    let supplied = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match supplied {
        Some(pw) if constant_time_eq(pw.as_bytes(), api_password.as_bytes()) => Ok(()),
        _ => Err(AppError::Auth("Invalid or missing API password".into())),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn authorize_requires_matching_bearer_password() {
        let ok = TestRequest::default()
            .insert_header((header::AUTHORIZATION, "Bearer s3cret"))
            .to_http_request();
        let wrong = TestRequest::default()
            .insert_header((header::AUTHORIZATION, "Bearer nope"))
            .to_http_request();
        let missing = TestRequest::default().to_http_request();

        assert!(authorize(&ok, "s3cret").is_ok());
        assert!(matches!(
            authorize(&wrong, "s3cret"),
            Err(AppError::Auth(_))
        ));
        assert!(matches!(
            authorize(&missing, "s3cret"),
            Err(AppError::Auth(_))
        ));
        assert!(matches!(authorize(&ok, ""), Err(AppError::Forbidden(_))));
    }
}
