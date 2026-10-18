use actix_cors::Cors;
use actix_web::middleware::{from_fn, Logger};
use actix_web::{web, App, HttpServer};
use std::sync::Arc;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod error;
mod metrics;
mod models;
mod proxy;
mod utils;

use auth::middleware::AuthMiddleware;
use config::Config;
use metrics::{dashboard, AppMetrics};
use proxy::{handler, stream::StreamManager};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load config first so log_level from APP__LOG_LEVEL is available.
    let config = Config::from_env().expect("Failed to load configuration");

    // RUST_LOG takes precedence; fall back to config.log_level.
    let log_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone());

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(log_filter))
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_span_events(FmtSpan::NONE),
        )
        .try_init()
        .expect("Failed to initialize logging");

    // Loud warning when no API password is configured — silent no-auth mode is
    // the most common footgun: any token-bearing request returns a cryptic 500
    // rather than streaming, and operators chase ghosts.
    if config.auth.api_password.is_empty() {
        tracing::warn!(
            "APP__AUTH__API_PASSWORD is not set — server is running in no-auth mode. \
             Requests that carry an encrypted `?token=...` (or `/_token_/...` path) \
             will be rejected with an explanatory 401, and callers must use direct \
             `?d=<url>&h_*=...` mode. Set APP__AUTH__API_PASSWORD to enable \
             token-based auth."
        );
    }

    let auth_middleware = AuthMiddleware::new(config.auth.api_password.clone());
    let app_metrics = AppMetrics::new();
    metrics::history::spawn_sampler(app_metrics.clone());
    let stream_manager =
        StreamManager::new(config.proxy.clone()).with_upstream_stats(app_metrics.upstream.clone());

    let forward_config = web::Data::new(config.forward.clone());
    let server_config = Arc::new(config.clone());

    tracing::info!(
        "Starting MediaFlow Proxy Light on {}:{}",
        server_config.server.host,
        server_config.server.port
    );

    HttpServer::new(move || {
        let config = Arc::clone(&server_config);
        let metrics = app_metrics.clone();

        App::new()
            // Path only (`%U`, not `%r`): query strings carry `api_password`
            // and upstream URLs, which have no business in access logs.
            .wrap(
                Logger::new("%a - \"%{method}xi %U\" %s")
                    .custom_request_replace("method", |req| req.method().to_string())
                    .exclude("/dashboard/stats")
                    .exclude("/dashboard/history"),
            )
            // Compress::default() is intentionally omitted: the proxy streams
            // binary media (video/audio) that is already compressed.  Applying
            // gzip/brotli to such data burns CPU with zero gain and — worse —
            // actix's Compress wrapper buffers each streaming chunk before
            // encoding, which badly hurts streaming throughput.
            // Traffic meter sits inside auth so only authenticated traffic counts.
            .wrap(from_fn(metrics::traffic::traffic_meter))
            .wrap(auth_middleware.clone())
            .app_data(web::Data::new(stream_manager.clone()))
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(metrics))
            .app_data(forward_config.clone())
            // Batch URL generation (AIOStreams)
            .service(
                web::resource("/generate_urls")
                    .wrap(Cors::permissive())
                    .route(web::post().to(handler::generate_urls)),
            )
            // Health check
            .service(web::scope("/health").route("", web::get().to(|| async { "OK" })))
            // Live usage dashboard; every route checks the session cookie
            // itself and stays out of CORS (see `dashboard::routes`).
            .configure(dashboard::routes)
            // Generic /proxy scope (AIOStreams: stream + public IP); players
            // and web clients need permissive CORS here.
            .service(
                web::scope("/proxy")
                    .wrap(Cors::permissive())
                    .route("/stream", web::get().to(handler::proxy_stream_get))
                    .route("/stream", web::head().to(handler::proxy_stream_head))
                    .route(
                        "/stream/{filename:.*}",
                        web::get().to(handler::proxy_stream_get),
                    )
                    .route(
                        "/stream/{filename:.*}",
                        web::head().to(handler::proxy_stream_head),
                    )
                    .route("/ip", web::get().to(handler::get_public_ip)),
            )
            .default_service(web::route().to(|| async {
                actix_web::HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Not Found"
                }))
            }))
    })
    .workers(config.server.workers)
    .bind((config.server.host.as_str(), config.server.port))?
    .run()
    .await
}
