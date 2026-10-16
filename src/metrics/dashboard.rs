//! Backend for the web dashboard (`static/dashboard.html`).
//!
//! - `GET /dashboard`       — redirect to the dashboard page
//! - `GET /dashboard/stats` — tiny JSON snapshot, polled by the page
//!
//! The stats endpoint authenticates itself with `Authorization: Bearer
//! <api_password>` — a header rather than `?api_password=` so the secret
//! doesn't land in the access log on every poll. It is refused outright when
//! no `api_password` is configured, so the dashboard is never public.
//!
//! Bandwidth is deliberately not computed here: the page derives it from
//! successive `bytes_out` samples, which keeps the server stateless.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use actix_web::{http::header, web, HttpRequest, HttpResponse};
use serde::Serialize;

use super::AppMetrics;
use crate::config::Config;
use crate::error::{AppError, AppResult};

#[derive(Serialize)]
struct DashboardStats {
    uptime_secs: u64,
    /// Resident memory of this process; `null` on unsupported platforms.
    memory_rss_bytes: Option<u64>,
    active_clients: usize,
    active_streams: u64,
    bytes_out: u64,
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

    Ok(HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(DashboardStats {
            uptime_secs: metrics.uptime_secs(),
            memory_rss_bytes: resident_memory_bytes(),
            active_clients: metrics.active_clients(),
            active_streams: metrics.active_connections.load(Ordering::Relaxed),
            bytes_out: metrics.bytes_out.load(Ordering::Relaxed),
        }))
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

/// Resident set size of this process, in bytes.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn resident_memory_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(kib * 1024)
}

/// Resident set size of this process, in bytes.
#[cfg(target_vendor = "apple")]
fn resident_memory_bytes() -> Option<u64> {
    let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` is a writable buffer of exactly `size` bytes, which is
    // what PROC_PIDTASKINFO fills; it is only read after a full-size write.
    let written = unsafe {
        libc::proc_pidinfo(
            std::process::id() as libc::c_int,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    (written == size).then(|| unsafe { info.assume_init() }.pti_resident_size)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn resident_memory_bytes() -> Option<u64> {
    None
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

    #[test]
    fn reads_resident_memory_where_supported() {
        if cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple"
        )) {
            assert!(resident_memory_bytes().is_some_and(|b| b > 0));
        }
    }
}
