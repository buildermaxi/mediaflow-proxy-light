//! The web dashboard, served at the root.
//!
//! - `GET  /`                  — dashboard page, or the sign-in page without a session
//! - `POST /login`             — check the API password, set the session cookie
//!   (`GET /login` just redirects to `/`)
//! - `POST /logout`            — clear the session cookie
//! - `GET  /dashboard/stats`   — live snapshot, polled every couple of seconds
//! - `GET  /dashboard/history` — last 24 h in 5-minute buckets, polled each minute
//!
//! Every route checks the session cookie server-side (see
//! [`crate::auth::session`]); the feeds answer 401 without one. Nothing is
//! reachable when no `api_password` is configured, so the dashboard is never
//! public. [`routes`] keeps them out of the CORS layer, so other origins can't
//! read any of it.
//!
//! Live rates (bandwidth, CPU, per-client speed) are not computed here: the
//! page derives them from successive cumulative counters.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use actix_web::{http::header, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use super::{clients::ClientView, system, upstream::HostView, AppMetrics, StreamKind};
use crate::auth::session;
use crate::config::Config;
use crate::error::{AppError, AppResult};

const DASHBOARD_HTML: &str = include_str!("../../static/dashboard.html");
const LOGIN_HTML: &str = include_str!("../../static/login.html");

/// Registers the dashboard routes. Keep them out of any CORS layer: the proxy
/// routes use a permissive policy *with credentials*, and `SameSite` can't tell
/// this origin from a sibling subdomain or another port on the same host, so
/// with CORS a page there could read the dashboard with the session cookie.
pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(dashboard_page_handler))
        .route("/login", web::post().to(login_handler))
        .route("/login", web::get().to(login_redirect_handler))
        .route("/logout", web::post().to(logout_handler))
        .route("/dashboard/stats", web::get().to(dashboard_stats_handler))
        .route(
            "/dashboard/history",
            web::get().to(dashboard_history_handler),
        );
}

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
}

#[derive(Serialize)]
struct KindStats {
    kind: StreamKind,
    bytes: u64,
    open_streams: u64,
}

pub async fn dashboard_page_handler(
    req: HttpRequest,
    config: web::Data<Arc<Config>>,
) -> HttpResponse {
    let api_password = &config.auth.api_password;
    if session::is_authenticated(&req, api_password) {
        html(&mut HttpResponse::Ok(), DASHBOARD_HTML.to_string())
    } else if api_password.is_empty() {
        login_page(HttpResponse::Forbidden(), DISABLED)
    } else {
        login_page(HttpResponse::Ok(), "")
    }
}

#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
}

pub async fn login_handler(
    req: HttpRequest,
    form: web::Form<LoginForm>,
    config: web::Data<Arc<Config>>,
) -> HttpResponse {
    let api_password = &config.auth.api_password;
    if api_password.is_empty() {
        return login_page(HttpResponse::Forbidden(), DISABLED);
    }
    if !session::password_matches(&form.password, api_password) {
        return login_page(HttpResponse::Unauthorized(), "Wrong API password.");
    }
    // 303 back to the root (relative, so a reverse-proxy path prefix survives).
    HttpResponse::SeeOther()
        .cookie(session::login_cookie(&req, api_password))
        .insert_header((header::LOCATION, "./"))
        .finish()
}

/// A reload after a failed sign-in lands here; send it back to the root.
pub async fn login_redirect_handler() -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((header::LOCATION, "./"))
        .finish()
}

pub async fn logout_handler(req: HttpRequest) -> HttpResponse {
    HttpResponse::SeeOther()
        .cookie(session::logout_cookie(&req))
        .insert_header((header::LOCATION, "./"))
        .finish()
}

const DISABLED: &str = "Dashboard disabled: set API_PASSWORD on the server.";

/// The sign-in page with a fixed (never user-supplied) error message.
fn login_page(mut builder: actix_web::HttpResponseBuilder, error: &'static str) -> HttpResponse {
    html(&mut builder, LOGIN_HTML.replace("<!--error-->", error))
}

fn html(builder: &mut actix_web::HttpResponseBuilder, body: String) -> HttpResponse {
    builder
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::X_FRAME_OPTIONS, "DENY"))
        .content_type("text/html; charset=utf-8")
        .body(body)
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

fn authorize(req: &HttpRequest, api_password: &str) -> AppResult<()> {
    if session::is_authenticated(req, api_password) {
        Ok(())
    } else {
        Err(AppError::Auth("Not signed in".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::encryption::{EncryptionHandler, ProxyData};
    use crate::auth::middleware::AuthMiddleware;
    use actix_cors::Cors;
    use actix_web::{cookie::Cookie, http::StatusCode, test, App};

    const PASSWORD: &str = "s3cret";

    fn config(api_password: &str) -> Arc<Config> {
        let mut config = Config::from_env().expect("default config");
        config.auth.api_password = api_password.to_string();
        Arc::new(config)
    }

    macro_rules! app {
        ($api_password:expr) => {
            // Same layout as main.rs: dashboard routes outside CORS, a
            // CORS-wrapped /proxy scope next to them.
            test::init_service(
                App::new()
                    .wrap(AuthMiddleware::new($api_password.to_string()))
                    .app_data(web::Data::new(config($api_password)))
                    .app_data(web::Data::new(AppMetrics::new()))
                    .configure(routes)
                    .service(
                        web::scope("/proxy")
                            .wrap(Cors::permissive())
                            .route("/ip", web::get().to(|| async { "ip" })),
                    ),
            )
            .await
        };
    }

    fn login(password: &str) -> test::TestRequest {
        test::TestRequest::post()
            .uri("/login")
            .set_form([("password", password)])
    }

    #[actix_web::test]
    async fn everything_is_locked_without_a_session() {
        let app = app!(PASSWORD);

        let res = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = test::read_body(res).await;
        assert!(std::str::from_utf8(&body).unwrap().contains("Sign in"));

        for uri in ["/dashboard/stats", "/dashboard/history"] {
            let res =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{uri}");

            // Neither the password itself (old Bearer scheme, query param,
            // raw cookie) nor a forged cookie opens the feeds.
            for req in [
                test::TestRequest::get()
                    .uri(uri)
                    .insert_header((header::AUTHORIZATION, format!("Bearer {PASSWORD}"))),
                test::TestRequest::get().uri(&format!("{uri}?api_password={PASSWORD}")),
                test::TestRequest::get()
                    .uri(uri)
                    .cookie(Cookie::new(session::COOKIE_NAME, PASSWORD)),
            ] {
                let res = test::call_service(&app, req.to_request()).await;
                assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{uri}");
            }
        }
    }

    #[actix_web::test]
    async fn login_sets_a_session_that_opens_the_dashboard() {
        let app = app!(PASSWORD);

        let res = test::call_service(&app, login("wrong").to_request()).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.response().cookies().next().is_none());

        let res = test::call_service(&app, login(PASSWORD).to_request()).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let cookie = res
            .response()
            .cookies()
            .find(|c| c.name() == session::COOKIE_NAME)
            .expect("session cookie")
            .into_owned();
        assert!(cookie.http_only().unwrap_or(false));
        assert_ne!(cookie.value(), PASSWORD);

        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = test::read_body(res).await;
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("dashboard/stats"));

        for uri in ["/dashboard/stats", "/dashboard/history"] {
            let res = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(uri)
                    .cookie(cookie.clone())
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), StatusCode::OK, "{uri}");
        }

        let res =
            test::call_service(&app, test::TestRequest::get().uri("/login").to_request()).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/logout")
                .cookie(cookie)
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let cleared = res
            .response()
            .cookies()
            .find(|c| c.name() == session::COOKIE_NAME)
            .expect("removal cookie");
        assert_eq!(cleared.value(), "");
    }

    #[actix_web::test]
    async fn other_origins_cannot_read_the_dashboard() {
        let app = app!(PASSWORD);
        let res = test::call_service(&app, login(PASSWORD).to_request()).await;
        let cookie = res
            .response()
            .cookies()
            .find(|c| c.name() == session::COOKIE_NAME)
            .expect("session cookie")
            .into_owned();

        // Any stream token (they appear in every generated URL) passes the
        // auth middleware, which then rewrites `/_token_…/<path>`.
        let token = EncryptionHandler::new(PASSWORD.as_bytes())
            .unwrap()
            .encrypt(&ProxyData {
                destination: "https://example.com/movie.mkv".into(),
                query_params: None,
                request_headers: None,
                response_headers: None,
                exp: None,
                ip: None,
            })
            .unwrap();

        // A page on another port of the same host is "same-site", so the
        // browser sends the cookie; without CORS headers it can't read the
        // body — however the path is spelled.
        for uri in [
            "/".to_string(),
            "/dashboard/stats".to_string(),
            "/dashboard/history".to_string(),
            format!("/dashboard/%73tats?api_password={PASSWORD}"),
            format!("/_token_{token}/dashboard/stats"),
            format!("/_token_{token}/dashboard/%73tats"),
        ] {
            let res = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(&uri)
                    .cookie(cookie.clone())
                    .insert_header((header::ORIGIN, "http://127.0.0.1:3000"))
                    .to_request(),
            )
            .await;
            assert_eq!(
                res.status(),
                StatusCode::OK,
                "{uri} must reach the dashboard"
            );
            let headers = res.headers();
            assert!(
                !headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    && !headers.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
                "{uri} must not be readable cross-origin"
            );
        }

        // Proxy routes keep the permissive CORS that players rely on.
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/proxy/ip?api_password={PASSWORD}"))
                .insert_header((header::ORIGIN, "http://127.0.0.1:3000"))
                .to_request(),
        )
        .await;
        assert!(res
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    #[actix_web::test]
    async fn dashboard_is_disabled_without_an_api_password() {
        let app = app!("");

        let res = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = test::call_service(&app, login("").to_request()).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/dashboard/stats")
                .cookie(Cookie::new(session::COOKIE_NAME, ""))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
}
