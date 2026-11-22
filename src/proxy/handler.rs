use actix_web::{
    body::SizedStream,
    web::{self, Bytes},
    HttpRequest, HttpResponse,
};
use futures::stream;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::boxed::Box;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use crate::{
    auth::encryption::ProxyData,
    config::ForwardConfig,
    error::{AppError, AppResult},
    models::request::{SUPPORTED_REQUEST_HEADERS, SUPPORTED_RESPONSE_HEADERS},
    proxy::stream::{ResponseStream, StreamManager},
};

/// Streams `proxy_data.destination` back to the client: the player's
/// `Range` / `If-Range` go upstream, the upstream status (200, 206…) and a
/// fixed set of response headers come back.
async fn handle_proxy_request(
    req: HttpRequest,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
    is_head: bool,
) -> AppResult<HttpResponse> {
    // Never empty: the token is refused without a destination.
    let destination = proxy_data.destination.clone();

    // Only the player's seek headers are forwarded.
    let mut request_headers = HeaderMap::new();
    for &header_name in SUPPORTED_REQUEST_HEADERS {
        if let Some(value) = req.headers().get(header_name) {
            request_headers.insert(
                HeaderName::from_str(header_name)
                    .map_err(|e| AppError::Internal(format!("Invalid header name: {}", e)))?,
                HeaderValue::try_from(value.as_bytes())
                    .map_err(|e| AppError::Internal(format!("Invalid header value: {}", e)))?,
            );
        }
    }

    tracing::debug!("Request headers: {:?}", request_headers);

    // Create the stream — also get the upstream status code so we can mirror 206 etc.
    let (upstream_status, upstream_headers, stream_opt) = stream_manager
        .create_stream(destination, request_headers, is_head)
        .await?;

    tracing::debug!(
        "Upstream status: {}, headers: {:?}",
        upstream_status,
        upstream_headers
    );

    // Mirror the upstream status code (200 OK or 206 Partial Content for seeks)
    let mut response = HttpResponse::build(
        actix_web::http::StatusCode::from_u16(upstream_status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::OK),
    );

    // Add supported headers from upstream response
    for &header_name in SUPPORTED_RESPONSE_HEADERS {
        if let Some(value) = upstream_headers.get(header_name) {
            if let Ok(converted_value) =
                actix_web::http::header::HeaderValue::from_str(value.to_str().unwrap_or_default())
            {
                response.insert_header((header_name, converted_value));
            }
        }
    }

    // Get content length from headers
    let content_length = upstream_headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    if is_head {
        let empty_stream = Box::pin(stream::empty::<Result<Bytes, std::io::Error>>());
        Ok(response
            .no_chunking(content_length)
            .body(SizedStream::new(content_length, empty_stream)))
    } else if let Some(stream) = stream_opt {
        let response_stream = ResponseStream::new(stream_manager.stream_with_progress(stream));
        if content_length > 0 {
            Ok(response
                .no_chunking(content_length)
                .body(SizedStream::new(content_length, response_stream)))
        } else {
            Ok(response.streaming(response_stream))
        }
    } else {
        Err(AppError::Internal("Stream not available".to_string()))
    }
}

/// `GET /proxy/stream[/<filename>]`, reached through a `/_token_…/` URL: the
/// destination comes from the token (the filename segment is cosmetic, for
/// players that show or sniff it).
pub async fn proxy_stream_get(
    req: HttpRequest,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
) -> AppResult<HttpResponse> {
    handle_proxy_request(req, stream_manager, proxy_data, false).await
}

pub async fn proxy_stream_head(
    req: HttpRequest,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
) -> AppResult<HttpResponse> {
    handle_proxy_request(req, stream_manager, proxy_data, true).await
}

// ---------------------------------------------------------------------------
// Public IP
// ---------------------------------------------------------------------------

// Asked in parallel; the first IPv4 answer wins. Looked up on every call, so
// the answer is the IP the streams actually leave from: the one AIO Reborn
// binds debrid links to (it caches it on its side). Debrid services are
// reached over IPv4, so an IPv6 answer is skipped.
const IP_LOOKUP_SERVICES: &[(&str, &str)] = &[
    ("https://api.ipify.org?format=json", "ip"),
    ("https://ipinfo.io/json", "ip"),
    ("https://httpbin.org/ip", "origin"),
];

/// Per-service cap. The services are asked at once, so the whole lookup ends
/// within this, well inside AIO Reborn's 10 s timeout.
const IP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);

/// The IPv4 address in a lookup answer (`httpbin` may list several,
/// comma-separated: the first one is the client).
fn ipv4_of(answer: &str) -> Option<Ipv4Addr> {
    answer.split(',').next()?.trim().parse().ok()
}

pub async fn get_public_ip(
    stream_manager: web::Data<StreamManager>,
    forward_cfg: web::Data<ForwardConfig>,
) -> AppResult<HttpResponse> {
    if let Some(ref ip) = forward_cfg.public_ip {
        return Ok(HttpResponse::Ok().json(serde_json::json!({ "ip": ip })));
    }
    let lookups = IP_LOOKUP_SERVICES.iter().map(|&(url, key)| {
        let stream_manager = stream_manager.clone();
        Box::pin(async move {
            let lookup = async {
                let resp = stream_manager
                    .make_request(url.to_string(), HeaderMap::new())
                    .await?;
                resp.json::<serde_json::Value>()
                    .await
                    .map_err(|e| AppError::Upstream(format!("body parse failed: {e}")))
            };
            match tokio::time::timeout(IP_LOOKUP_TIMEOUT, lookup).await {
                Ok(Ok(data)) => {
                    let answer = data.get(key).and_then(|v| v.as_str()).unwrap_or_default();
                    if let Some(ip) = ipv4_of(answer) {
                        return Ok(ip);
                    }
                    tracing::warn!("IP lookup {} returned no IPv4 '{}' field", url, key);
                }
                Ok(Err(e)) => tracing::warn!("IP lookup {} failed: {}", url, e),
                Err(_) => tracing::warn!(
                    "IP lookup {} timed out after {} s",
                    url,
                    IP_LOOKUP_TIMEOUT.as_secs()
                ),
            }
            Err(())
        })
    });
    if let Ok((ip, _)) = futures::future::select_ok(lookups).await {
        return Ok(HttpResponse::Ok().json(serde_json::json!({ "ip": ip.to_string() })));
    }

    Err(AppError::Upstream(
        "Failed to retrieve public IP from all services".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn only_ipv4_answers_are_used() {
        assert_eq!(ipv4_of("82.66.1.2"), Some(Ipv4Addr::new(82, 66, 1, 2)));
        assert_eq!(
            ipv4_of(" 82.66.1.2, 10.0.0.1"),
            Some(Ipv4Addr::new(82, 66, 1, 2))
        );
        assert_eq!(ipv4_of("2a01:e0a::1"), None);
        assert_eq!(ipv4_of(""), None);
    }

    #[actix_web::test]
    async fn configured_public_ip_wins() {
        let config = Config::from_env().expect("default config");
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(StreamManager::new(config.proxy.clone())))
                .app_data(web::Data::new(ForwardConfig {
                    public_ip: Some("203.0.113.9".into()),
                }))
                .route("/proxy/ip", web::get().to(get_public_ip)),
        )
        .await;
        let body: serde_json::Value = test::call_and_read_body_json(
            &app,
            test::TestRequest::get().uri("/proxy/ip").to_request(),
        )
        .await;
        assert_eq!(body, serde_json::json!({ "ip": "203.0.113.9" }));
    }
}
