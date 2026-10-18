use actix_web::{
    body::SizedStream,
    web::{self, Bytes},
    HttpRequest, HttpResponse,
};
use futures::stream;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::boxed::Box;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    auth::{encryption::ProxyData, EncryptionHandler},
    config::ForwardConfig,
    error::{AppError, AppResult},
    models::request::{SUPPORTED_REQUEST_HEADERS, SUPPORTED_RESPONSE_HEADERS},
    proxy::stream::{ResponseStream, StreamManager},
    utils::base64_url::{decode_base64_url, encode_url_to_base64},
};

async fn handle_proxy_request(
    req: HttpRequest,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
    is_head: bool,
    destination_override: Option<String>,
) -> AppResult<HttpResponse> {
    let destination = destination_override
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| proxy_data.destination.clone());

    if destination.is_empty() {
        return Err(AppError::BadRequest(
            "Missing destination URL. Provide `d=<url>` query param or an encrypted token.".into(),
        ));
    }

    // Prepare headers
    let mut request_headers = HeaderMap::new();

    // Add supported headers from original request
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

    // Add custom headers from proxy data
    if let Some(custom_headers) = &proxy_data.request_headers {
        for (key, value) in custom_headers
            .as_object()
            .unwrap_or(&serde_json::Map::new())
        {
            if let Some(value_str) = value.as_str() {
                request_headers.insert(
                    HeaderName::from_str(key)
                        .map_err(|e| AppError::Internal(format!("Invalid header name: {}", e)))?,
                    HeaderValue::from_str(value_str)
                        .map_err(|e| AppError::Internal(format!("Invalid header value: {}", e)))?,
                );
            }
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

    // Add custom response headers from proxy data
    if let Some(custom_headers) = &proxy_data.response_headers {
        for (key, value) in custom_headers
            .as_object()
            .unwrap_or(&serde_json::Map::new())
        {
            if let Some(value_str) = value.as_str() {
                response.insert_header((
                    actix_web::http::header::HeaderName::from_str(key)
                        .map_err(|e| AppError::Internal(format!("Invalid header name: {}", e)))?,
                    actix_web::http::header::HeaderValue::from_str(value_str)
                        .map_err(|e| AppError::Internal(format!("Invalid header value: {}", e)))?,
                ));
            }
        }
    }

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

/// Resolve the effective destination URL for a proxy stream request.
///
/// Priority:
/// 1. `proxy_data.destination` (from encrypted token or `d=` query param) — used as-is.
/// 2. `d=` query param is a base64url-encoded URL — decode and use it.
/// 3. `{filename}` path segment is a base64url-encoded URL — decode and use it.
fn resolve_stream_destination(req: &HttpRequest, proxy_data: &ProxyData) -> Option<String> {
    // Already set by token or plain d= param.
    if !proxy_data.destination.is_empty() {
        // The destination might itself be a base64-encoded URL (Aiostreams passes d=<b64>).
        let decoded = decode_base64_url(&proxy_data.destination);
        return Some(decoded.unwrap_or_else(|| proxy_data.destination.clone()));
    }

    // Try the {filename:.*} path segment as a base64url-encoded destination URL.
    if let Some(filename) = req.match_info().get("filename") {
        if !filename.is_empty() {
            if let Some(decoded) = decode_base64_url(filename) {
                return Some(decoded);
            }
        }
    }

    None
}

pub async fn proxy_stream_get(
    req: HttpRequest,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
) -> AppResult<HttpResponse> {
    let destination = resolve_stream_destination(&req, &proxy_data);
    handle_proxy_request(req, stream_manager, proxy_data, false, destination).await
}

pub async fn proxy_stream_head(
    req: HttpRequest,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
) -> AppResult<HttpResponse> {
    let destination = resolve_stream_destination(&req, &proxy_data);
    handle_proxy_request(req, stream_manager, proxy_data, true, destination).await
}

/// URL-building logic behind `POST /generate_urls`.
///
/// Encrypted tokens use Python's path format: `{base}/_token_{token}{endpoint_path}`.
/// Unencrypted tokens use flat query params matching Python's encode_mediaflow_proxy_url.
/// When `base64_encode_destination` is true and no `api_password` is provided, the
/// destination URL is base64url-encoded and embedded in the URL path instead of `d=`.
#[allow(clippy::too_many_arguments)]
pub fn build_proxy_url(
    mediaflow_proxy_url: &str,
    endpoint: Option<&str>,
    destination_url: &str,
    query_params: &HashMap<String, String>,
    request_headers: &HashMap<String, String>,
    response_headers: &HashMap<String, String>,
    propagate_response_headers: &HashMap<String, String>,
    remove_response_headers: &[String],
    stream_transformer: Option<&str>,
    filename: Option<&str>,
    api_password: Option<&str>,
    expiration: Option<u64>,
    ip: Option<&str>,
    base64_encode_destination: bool,
) -> AppResult<String> {
    let base = mediaflow_proxy_url.trim_end_matches('/');
    let endpoint_path = endpoint
        .filter(|ep| !ep.is_empty())
        .map(|ep| format!("/{}", ep.trim_start_matches('/')))
        .unwrap_or_default();

    if let Some(password) = api_password.filter(|p| !p.is_empty()) {
        let handler = EncryptionHandler::new(password.as_bytes()).map_err(|e| {
            AppError::Internal(format!("Failed to create encryption handler: {}", e))
        })?;

        let proxy_data = ProxyData {
            destination: destination_url.to_string(),
            query_params: Some(
                serde_json::to_value(query_params).map_err(AppError::SerdeJsonError)?,
            ),
            request_headers: Some(
                serde_json::to_value(request_headers).map_err(AppError::SerdeJsonError)?,
            ),
            response_headers: Some(
                serde_json::to_value(response_headers).map_err(AppError::SerdeJsonError)?,
            ),
            exp: expiration.map(|e| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + e
            }),
            ip: ip.map(|s| s.to_string()),
        };

        let token = handler.encrypt(&proxy_data)?;

        // Preserve the complete externally visible proxy base URL, including
        // path prefixes used by reverse proxies/CDNs.
        let mut url = format!("{}/_token_{}{}", base, token, endpoint_path);
        if let Some(fname) = filename {
            url = format!("{}/{}", url, urlencoding::encode(fname));
        }
        Ok(url)
    } else {
        // Unencrypted: flat query params matching Python's encode_mediaflow_proxy_url.
        // When base64_encode_destination is set, embed the destination as base64url in the
        // URL path (after the endpoint) instead of using a `d=` query parameter. This lets
        // clients like Aiostreams construct proxy URLs without query-string bookkeeping.
        let mut url = format!("{}{}", base, endpoint_path);

        let mut params: Vec<(String, String)> = if base64_encode_destination {
            // Destination goes into the path; no d= param.
            let b64 = encode_url_to_base64(destination_url);
            url = format!("{}/{}", url, b64);
            vec![]
        } else {
            // Standard: append filename (if any) then add d= query param.
            if let Some(fname) = filename {
                url = format!("{}/{}", url, urlencoding::encode(fname));
            }
            vec![("d".to_string(), destination_url.to_string())]
        };

        for (k, v) in query_params {
            if !v.is_empty() {
                params.push((k.clone(), v.clone()));
            }
        }

        for (k, v) in request_headers {
            if v.is_empty() {
                continue;
            }
            // Skip per-request dynamic headers (range, if-range) — baking them into
            // the URL would override the player's actual seek headers on playback.
            let k_lower = k.to_lowercase();
            let bare = k_lower.strip_prefix("h_").unwrap_or(&k_lower);
            if SUPPORTED_REQUEST_HEADERS.contains(&bare) {
                continue;
            }
            let prefixed = if k.starts_with("h_") {
                k.clone()
            } else {
                format!("h_{}", k)
            };
            params.push((prefixed, v.clone()));
        }

        for (k, v) in response_headers {
            if v.is_empty() {
                continue;
            }
            let prefixed = if k.starts_with("r_") {
                k.clone()
            } else {
                format!("r_{}", k)
            };
            params.push((prefixed, v.clone()));
        }

        for (k, v) in propagate_response_headers {
            if v.is_empty() {
                continue;
            }
            let prefixed = if k.starts_with("rp_") {
                k.clone()
            } else {
                format!("rp_{}", k)
            };
            params.push((prefixed, v.clone()));
        }

        if !remove_response_headers.is_empty() {
            params.push(("x_headers".to_string(), remove_response_headers.join(",")));
        }

        if let Some(transformer) = stream_transformer {
            params.push(("transformer".to_string(), transformer.to_string()));
        }

        if params.is_empty() {
            Ok(url)
        } else {
            let qs = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            Ok(format!("{}?{}", url, qs))
        }
    }
}

// Mirrors Python's IP_LOOKUP_SERVICES — tried in order; first success wins.
// Looked up through `StreamManager` on every call, so the answer is the IP the
// streams actually leave from (e.g. a WARP / SOCKS upstream proxy), which is
// what AIOStreams binds debrid links to. AIOStreams caches it on its side.
const IP_LOOKUP_SERVICES: &[(&str, &str)] = &[
    ("https://api.ipify.org?format=json", "ip"),
    ("https://ipinfo.io/json", "ip"),
    ("https://httpbin.org/ip", "origin"),
];

/// Per-service cap, so a stalled proxy (e.g. WARP up but its tunnel dead)
/// fails all three lookups well within AIOStreams' 30 s request timeout.
const IP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

pub async fn get_public_ip(
    stream_manager: web::Data<StreamManager>,
    forward_cfg: web::Data<ForwardConfig>,
) -> AppResult<HttpResponse> {
    if let Some(ref ip) = forward_cfg.public_ip {
        return Ok(HttpResponse::Ok().json(serde_json::json!({ "ip": ip })));
    }
    for (url, key) in IP_LOOKUP_SERVICES {
        let lookup = async {
            let resp = stream_manager
                .make_request((*url).to_string(), HeaderMap::new())
                .await?;
            resp.json::<serde_json::Value>()
                .await
                .map_err(|e| AppError::Upstream(format!("body parse failed: {e}")))
        };
        match tokio::time::timeout(IP_LOOKUP_TIMEOUT, lookup).await {
            Ok(Ok(data)) => {
                if let Some(ip) = data.get(*key).and_then(|v| v.as_str()) {
                    let ip = ip.trim();
                    if !ip.is_empty() {
                        return Ok(HttpResponse::Ok().json(serde_json::json!({ "ip": ip })));
                    }
                }
                tracing::warn!("IP lookup {} returned no '{}' field", url, key);
            }
            Ok(Err(e)) => tracing::warn!("IP lookup {} failed: {}", url, e),
            Err(_) => tracing::warn!(
                "IP lookup {} timed out after {} s",
                url,
                IP_LOOKUP_TIMEOUT.as_secs()
            ),
        }
    }

    Err(AppError::Upstream(
        "Failed to retrieve public IP from all services".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Multiple-URL generation
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
pub struct MultiUrlRequestItem {
    pub endpoint: Option<String>,
    pub destination_url: String,
    #[serde(default)]
    pub query_params: HashMap<String, String>,
    #[serde(default)]
    pub request_headers: HashMap<String, String>,
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
    #[serde(default)]
    pub propagate_response_headers: HashMap<String, String>,
    #[serde(default)]
    pub remove_response_headers: Vec<String>,
    pub stream_transformer: Option<String>,
    pub filename: Option<String>,
    #[serde(default)]
    pub base64_encode_destination: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct GenerateMultiUrlRequest {
    pub mediaflow_proxy_url: String,
    pub api_password: Option<String>,
    pub expiration: Option<u64>,
    pub ip: Option<String>,
    pub urls: Vec<MultiUrlRequestItem>,
}

pub async fn generate_urls(req: web::Json<GenerateMultiUrlRequest>) -> AppResult<HttpResponse> {
    let effective_password = req.api_password.as_deref().filter(|p| !p.is_empty());
    let mut encoded: Vec<String> = Vec::with_capacity(req.urls.len());

    for item in &req.urls {
        let url = build_proxy_url(
            &req.mediaflow_proxy_url,
            item.endpoint.as_deref(),
            &item.destination_url,
            &item.query_params,
            &item.request_headers,
            &item.response_headers,
            &item.propagate_response_headers,
            &item.remove_response_headers,
            item.stream_transformer.as_deref(),
            item.filename.as_deref(),
            effective_password,
            req.expiration,
            req.ip.as_deref(),
            item.base64_encode_destination,
        )?;
        encoded.push(url);
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({ "urls": encoded })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ForwardConfig};
    use actix_web::{test, App};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// The IP lookup must leave through the same upstream proxy as the streams,
    /// or AIOStreams binds debrid links to an IP that never fetches them.
    #[actix_web::test]
    async fn public_ip_lookup_goes_through_the_upstream_proxy() {
        // Fake HTTP proxy: records each request line and refuses the tunnel.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n]);
                log.lock()
                    .unwrap()
                    .push(line.lines().next().unwrap_or_default().to_string());
                let _ = socket
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });

        let mut config = Config::from_env().expect("default config");
        config.proxy.proxy_url = Some(proxy_url);
        config.proxy.all_proxy = true;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(StreamManager::new(config.proxy.clone())))
                .app_data(web::Data::new(ForwardConfig::default()))
                .route("/proxy/ip", web::get().to(get_public_ip)),
        )
        .await;

        let res =
            test::call_service(&app, test::TestRequest::get().uri("/proxy/ip").to_request()).await;
        assert!(
            res.status().is_server_error(),
            "the fake proxy refuses every tunnel"
        );
        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen.first().map(String::as_str),
            Some("CONNECT api.ipify.org:443 HTTP/1.1"),
            "lookup must go through the proxy: {seen:?}"
        );
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
