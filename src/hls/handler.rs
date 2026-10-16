/// Actix-web route handlers for HLS endpoints.
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::str::FromStr;

use crate::{
    auth::encryption::ProxyData,
    config::Config,
    error::AppResult,
    hls::manifest::{
        error_playlist, graceful_end_playlist, ManifestOptions, ManifestProcessor, ProxyParams,
    },
    hls::prebuffer::HlsPrebuffer,
    metrics::AppMetrics,
    proxy::stream::StreamManager,
    utils::url::public_proxy_base_url,
};

/// Extract passthrough params from `proxy_data`:
/// - `api_password` from query params inside `proxy_data.query_params`
/// - `h_*` request headers
fn extract_proxy_params(proxy_data: &ProxyData, config: &Config) -> ProxyParams {
    let api_password = config.auth.api_password.clone();

    let pass_headers = proxy_data
        .request_headers
        .as_ref()
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    ProxyParams::new(&api_password, pass_headers)
}

// ---------------------------------------------------------------------------
// Route: GET /proxy/hls/manifest
// ---------------------------------------------------------------------------

/// Fetch an upstream M3U8 playlist, rewrite URLs, and return the modified content.
pub async fn hls_manifest_handler(
    req: HttpRequest,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
    config: web::Data<Arc<Config>>,
    metrics: web::Data<Arc<AppMetrics>>,
    hls_prebuffer: web::Data<HlsPrebuffer>,
) -> AppResult<HttpResponse> {
    metrics.inc_request();
    metrics.hls_requests.fetch_add(1, Ordering::Relaxed);
    let requested_manifest_url = proxy_data.destination.clone();
    let proxy_base = public_proxy_base_url(&req, &config.server.path);
    let base_params = extract_proxy_params(&proxy_data, &config);

    // Extract manifest-processing options from query params
    let query_params: HashMap<String, String> =
        web::Query::<HashMap<String, String>>::from_query(req.query_string())
            .map(|q| q.into_inner())
            .unwrap_or_default();

    let opts = ManifestOptions {
        key_only_proxy: query_params
            .get("key_only_proxy")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
        no_proxy: query_params
            .get("no_proxy")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
        force_playlist_proxy: query_params
            .get("force_playlist_proxy")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
        start_offset: query_params
            .get("start_offset")
            .and_then(|v| v.parse::<f64>().ok()),
        force_start_offset: query_params.contains_key("start_offset"),
        skip_ranges: Vec::new(), // TODO: parse from query params in future
    };

    // Build request headers for upstream fetch
    let mut request_headers = HeaderMap::new();
    for (k, v) in &base_params.pass_headers {
        if let (Ok(name), Ok(value)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
            request_headers.insert(name, value);
        }
    }

    // Fetch the upstream M3U8
    let upstream_fetch = stream_manager
        .fetch_bytes_with_final_url(requested_manifest_url.clone(), request_headers)
        .await
        .map_err(|e| {
            tracing::warn!(
                "Failed to fetch HLS manifest from {}: {}",
                requested_manifest_url,
                e
            );
            e
        });

    let (content, effective_manifest_url) = match upstream_fetch {
        Ok(result) => result,
        Err(_) => {
            let body = graceful_end_playlist("Stream unavailable");
            return Ok(HttpResponse::Ok()
                .content_type("application/vnd.apple.mpegurl")
                .body(body));
        }
    };
    let params = base_params.with_playlist_url(&effective_manifest_url);

    // Process the M3U8
    // force_playlist_proxy routes all media entries as playlists, so segment
    // prebuffering would register unsafe/non-segment URLs.
    if req.method() == actix_web::http::Method::GET
        && !opts.no_proxy
        && !opts.key_only_proxy
        && !opts.force_playlist_proxy
    {
        let segment_urls = ManifestProcessor::media_segment_urls(&content, &effective_manifest_url)
            .into_iter()
            .take(config.hls.prebuffer_segments)
            .collect::<Vec<_>>();
        if !segment_urls.is_empty() {
            let prebuffer = hls_prebuffer.clone();
            let playlist_url = effective_manifest_url.clone();
            let headers = params.pass_headers.clone();
            tokio::spawn(async move {
                prebuffer
                    .register_playlist(&playlist_url, segment_urls, headers)
                    .await;
            });
        }
    }

    let processor = ManifestProcessor::new(&proxy_base, params, opts);
    let processed = processor.process(&content, &effective_manifest_url);

    // Validate that we got a real M3U8
    if !processed.contains("#EXTM3U") {
        let body = error_playlist("Invalid upstream response");
        return Ok(HttpResponse::Ok()
            .content_type("application/vnd.apple.mpegurl")
            .body(body));
    }

    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .insert_header(("cache-control", "no-cache, no-store"))
        .body(processed))
}

// ---------------------------------------------------------------------------
// Route: GET /proxy/hls/playlist  (alias / sub-playlist endpoint)
// ---------------------------------------------------------------------------

/// Same logic as `hls_manifest_handler` — used for sub-playlist fetches.
pub async fn hls_playlist_handler(
    req: HttpRequest,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
    config: web::Data<Arc<Config>>,
    metrics: web::Data<Arc<AppMetrics>>,
    hls_prebuffer: web::Data<HlsPrebuffer>,
) -> AppResult<HttpResponse> {
    hls_manifest_handler(
        req,
        stream_manager,
        proxy_data,
        config,
        metrics,
        hls_prebuffer,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::encryption::EncryptionHandler,
        auth::middleware::AuthMiddleware,
        config::{
            AcestreamConfig, AuthConfig, Config, DrmConfig, EpgConfig, ExtractorConfig, HlsConfig,
            MpdConfig, ProxyConfig, RedisConfig, ServerConfig, TelegramConfig, TranscodeConfig,
        },
    };
    use actix_web::{test, App};
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{sleep, Duration, Instant};

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                workers: 1,
                path: String::new(),
            },
            proxy: ProxyConfig {
                connect_timeout: 5,
                buffer_size: 8192,
                follow_redirects: true,
                proxy_url: None,
                all_proxy: false,
                transport_routes: HashMap::new(),
                request_timeout_factor: 2,
                max_concurrent_per_host: 0,
                pool_idle_timeout: 5,
                pool_max_idle_per_host: 5,
                body_read_timeout: 5,
            },
            auth: AuthConfig {
                api_password: "secret".to_string(),
            },
            hls: HlsConfig {
                prebuffer_segments: 2,
                prebuffer_cache_size: 10,
                segment_cache_ttl: 60,
                inactivity_timeout: 60,
            },
            mpd: MpdConfig::default(),
            drm: DrmConfig::default(),
            redis: RedisConfig::default(),
            telegram: TelegramConfig::default(),
            acestream: AcestreamConfig::default(),
            transcode: TranscodeConfig::default(),
            epg: EpgConfig::default(),
            extractor: ExtractorConfig::default(),
            forward: crate::config::ForwardConfig::default(),
            log_level: "info".to_string(),
        })
    }

    async fn start_redirect_playlist_server() -> (String, String, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");
        let requested_manifest_url = format!("{base_url}/origin/manifest.m3u8");
        let effective_manifest_url = format!("{base_url}/edge/live/manifest.m3u8");

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let effective_manifest_url = effective_manifest_url.clone();
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");

                    let (status, headers, body) = match path {
                        "/origin/manifest.m3u8" => (
                            "302 Found",
                            format!("Location: {effective_manifest_url}\r\nConnection: close\r\n"),
                            Vec::new(),
                        ),
                        "/edge/live/manifest.m3u8" => (
                            "200 OK",
                            "Content-Type: application/vnd.apple.mpegurl\r\nConnection: close\r\n"
                                .to_string(),
                            b"#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6.0,\nsegments/seg001.ts\n#EXT-X-ENDLIST\n"
                                .to_vec(),
                        ),
                        "/edge/live/segments/seg001.ts" => (
                            "200 OK",
                            "Content-Type: video/mp2t\r\nConnection: close\r\n".to_string(),
                            b"segment-001".to_vec(),
                        ),
                        _ => (
                            "404 Not Found",
                            "Content-Type: text/plain\r\nConnection: close\r\n".to_string(),
                            b"not found".to_vec(),
                        ),
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    if !body.is_empty() {
                        let _ = socket.write_all(&body).await;
                    }
                    let _ = socket.shutdown().await;
                });
            }
        });

        (
            requested_manifest_url,
            format!("{base_url}/edge/live/manifest.m3u8"),
            format!("{base_url}/edge/live/segments/seg001.ts"),
        )
    }

    async fn wait_for_prefetch_registration(prebuffer: &HlsPrebuffer, playlist_url: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if prebuffer.queue_snapshot(playlist_url).await.is_some() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for prebuffer registration for {playlist_url}"
            );
            sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_for_cached_segment(prebuffer: &HlsPrebuffer, segment_url: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if prebuffer
                .get_cached_segment(segment_url, &HashMap::new())
                .await
                .is_some()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for cached segment {segment_url}"
            );
            sleep(Duration::from_millis(20)).await;
        }
    }

    fn extract_token_from_url(url: &str) -> &str {
        let (_, rest) = url
            .split_once("/_token_")
            .unwrap_or_else(|| panic!("expected tokenized URL, got: {url}"));
        let end = rest.find('/').unwrap_or(rest.len());
        &rest[..end]
    }

    #[actix_web::test]
    async fn manifest_handler_uses_effective_manifest_url_for_rewrite_and_prebuffer() {
        let (requested_manifest_url, effective_manifest_url, effective_segment_url) =
            start_redirect_playlist_server().await;
        let config = test_config();
        let stream_manager = web::Data::new(StreamManager::new(config.proxy.clone()));
        let metrics = web::Data::new(AppMetrics::new());
        let prebuffer = web::Data::new(HlsPrebuffer::new(crate::hls::prebuffer::PrebufferConfig {
            segments_ahead: 1,
            max_prefetchers: 10,
            inactivity_timeout: Duration::from_secs(60),
            segment_cache_ttl: Duration::from_secs(60),
        }));

        let app = test::init_service(
            App::new()
                .app_data(stream_manager.clone())
                .app_data(web::Data::new(config.clone()))
                .app_data(metrics)
                .app_data(prebuffer.clone())
                .wrap(AuthMiddleware::new("secret".into()))
                .service(
                    web::scope("/proxy/hls")
                        .route("/manifest.m3u8", web::get().to(hls_manifest_handler)),
                ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!(
                "/proxy/hls/manifest.m3u8?api_password=secret&d={}",
                urlencoding::encode(&requested_manifest_url)
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        let segment_proxy_url = body
            .lines()
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .expect("expected segment line in playlist");
        assert!(segment_proxy_url.starts_with("http://"));
        assert!(segment_proxy_url.contains("/_token_"));
        assert!(segment_proxy_url.ends_with("/proxy/hls/segment.ts"));

        let token = extract_token_from_url(segment_proxy_url);
        let pd = EncryptionHandler::new(b"secret")
            .unwrap()
            .decrypt(token, None)
            .unwrap();
        assert_eq!(pd.destination, effective_segment_url);
        assert_eq!(
            pd.query_params
                .as_ref()
                .and_then(|v| v.get("playlist_url"))
                .and_then(|v| v.as_str()),
            Some(effective_manifest_url.as_str())
        );

        wait_for_prefetch_registration(&prebuffer, &effective_manifest_url).await;
        wait_for_cached_segment(&prebuffer, &effective_segment_url).await;
        assert_eq!(
            prebuffer.queue_snapshot(&requested_manifest_url).await,
            None
        );
    }
}
