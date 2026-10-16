use actix_web::{
    body::SizedStream,
    http::StatusCode,
    web::{self, Bytes},
    HttpRequest, HttpResponse,
};
use futures::stream;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::boxed::Box;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use serde::Deserialize;

use crate::{
    auth::{encryption::ProxyData, EncryptionHandler},
    config::ForwardConfig,
    error::{AppError, AppResult},
    metrics::AppMetrics,
    models::request::{GenerateUrlRequest, SUPPORTED_REQUEST_HEADERS, SUPPORTED_RESPONSE_HEADERS},
    proxy::stream::{ResponseStream, StreamManager},
    utils::base64_url::{decode_base64_url, encode_url_to_base64, is_base64_url},
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
    metrics: web::Data<Arc<AppMetrics>>,
) -> AppResult<HttpResponse> {
    metrics.inc_request();
    metrics
        .proxy_stream_requests
        .fetch_add(1, Ordering::Relaxed);
    let destination = resolve_stream_destination(&req, &proxy_data);
    handle_proxy_request(req, stream_manager, proxy_data, false, destination).await
}

pub async fn proxy_stream_head(
    req: HttpRequest,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
    metrics: web::Data<Arc<AppMetrics>>,
) -> AppResult<HttpResponse> {
    metrics.inc_request();
    metrics
        .proxy_stream_requests
        .fetch_add(1, Ordering::Relaxed);
    let destination = resolve_stream_destination(&req, &proxy_data);
    handle_proxy_request(req, stream_manager, proxy_data, true, destination).await
}

// Headers that must not be forwarded upstream (they'd leak the caller's IP).
const IP_DISCLOSURE_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "forwarded",
    "cf-connecting-ip",
    "x-original-forwarded-for",
    "x-cluster-client-ip",
];

// Hop-by-hop headers that must not be propagated to/from the upstream.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

// Headers that callers must not inject via h_* params — they enable host-header
// injection, HTTP request smuggling, or break reqwest's own framing logic.
const BLOCKED_REQUEST_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "content-encoding",
];

fn check_forward_destination(url: &str, cfg: &ForwardConfig) -> AppResult<()> {
    let parsed = Url::parse(url)
        .map_err(|_| AppError::BadRequest(format!("Invalid destination URL: {url}")))?;

    // Only allow http(s) — blocks file://, ftp://, gopher://, etc.
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(AppError::BadRequest(format!(
            "Invalid URL scheme '{scheme}'. Only http and https are allowed."
        )));
    }

    let hostname = parsed.host_str().unwrap_or("").to_lowercase();
    if hostname.is_empty() {
        return Err(AppError::BadRequest(
            "Invalid destination URL: no hostname".into(),
        ));
    }

    // Allowlist check
    if !cfg.allowed_hosts.is_empty() {
        let allowed: std::collections::HashSet<_> =
            cfg.allowed_hosts.iter().map(|h| h.to_lowercase()).collect();
        if !allowed.contains(&hostname) {
            return Err(AppError::Forbidden(format!(
                "Host '{hostname}' is not in forward_allowed_hosts"
            )));
        }
    }

    // Denylist check
    let denied: std::collections::HashSet<_> =
        cfg.denied_hosts.iter().map(|h| h.to_lowercase()).collect();
    if denied.contains(&hostname) {
        return Err(AppError::Forbidden(format!("Host '{hostname}' is denied")));
    }

    // Block loopback hostnames
    if matches!(
        hostname.as_str(),
        "localhost" | "ip6-localhost" | "ip6-loopback"
    ) {
        return Err(AppError::Forbidden(
            "Forwarding to localhost is not allowed".into(),
        ));
    }

    // Block private/loopback/link-local IPs given as literals
    if let Ok(addr) = hostname.parse::<IpAddr>() {
        if addr.is_loopback() || addr.is_multicast() || is_private_ip(&addr) {
            return Err(AppError::Forbidden(
                "Forwarding to private/loopback addresses is not allowed".into(),
            ));
        }
    }

    Ok(())
}

fn is_private_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || {
                    // fc00::/7 — unique local
                    let octets = v6.octets();
                    (octets[0] & 0xfe) == 0xfc
                }
                || {
                    // fe80::/10 — link-local
                    let octets = v6.octets();
                    (octets[0] == 0xfe) && ((octets[1] & 0xc0) == 0x80)
                }
        }
    }
}

pub async fn proxy_forward(
    req: HttpRequest,
    body: Bytes,
    stream_manager: web::Data<StreamManager>,
    proxy_data: web::ReqData<ProxyData>,
    forward_cfg: web::Data<ForwardConfig>,
) -> AppResult<HttpResponse> {
    let destination = if !proxy_data.destination.is_empty() {
        decode_base64_url(&proxy_data.destination).unwrap_or_else(|| proxy_data.destination.clone())
    } else {
        return Err(AppError::BadRequest(
            "Missing destination URL. Provide `d=<url>` query param or an encrypted token.".into(),
        ));
    };

    check_forward_destination(&destination, &forward_cfg)?;

    // Substitute {mediaflow_ip} with MediaFlow's own public IP so debrid services
    // receive a consistent ip= parameter that matches the TCP source IP.
    const IP_PLACEHOLDER: &str = "{mediaflow_ip}";
    let (destination, body) = if let Some(ref public_ip) = forward_cfg.public_ip {
        let new_dest = if destination.contains(IP_PLACEHOLDER) {
            destination.replace(IP_PLACEHOLDER, public_ip)
        } else {
            destination
        };
        let new_body = if !body.is_empty()
            && body
                .windows(IP_PLACEHOLDER.len())
                .any(|w| w == IP_PLACEHOLDER.as_bytes())
        {
            // Binary-safe byte-level replacement — no UTF-8 conversion that could
            // corrupt multipart or other binary payloads.
            let needle = IP_PLACEHOLDER.as_bytes();
            let replacement = public_ip.as_bytes();
            let mut out: Vec<u8> = Vec::with_capacity(body.len());
            let mut i = 0;
            while i < body.len() {
                if body[i..].starts_with(needle) {
                    out.extend_from_slice(replacement);
                    i += needle.len();
                } else {
                    out.push(body[i]);
                    i += 1;
                }
            }
            Bytes::from(out)
        } else {
            body
        };
        (new_dest, new_body)
    } else {
        (destination, body)
    };

    // Build outbound headers from proxy_data (h_* params), stripping IP-disclosure ones.
    let mut request_headers = HeaderMap::new();
    if let Some(custom_headers) = &proxy_data.request_headers {
        for (key, value) in custom_headers
            .as_object()
            .unwrap_or(&serde_json::Map::new())
        {
            let key_lower = key.to_lowercase();
            if IP_DISCLOSURE_HEADERS.contains(&key_lower.as_str()) {
                continue;
            }
            if HOP_BY_HOP_HEADERS.contains(&key_lower.as_str()) {
                continue;
            }
            if BLOCKED_REQUEST_HEADERS.contains(&key_lower.as_str()) {
                continue;
            }
            if let Some(value_str) = value.as_str() {
                if let (Ok(name), Ok(val)) =
                    (HeaderName::from_str(key), HeaderValue::from_str(value_str))
                {
                    request_headers.insert(name, val);
                }
            }
        }
    }

    if body.len() > forward_cfg.max_request_body_bytes {
        return Err(AppError::BadRequest("Request body too large".into()));
    }

    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    let upstream = stream_manager
        .forward_request(method, destination, request_headers, body)
        .await?;

    let upstream_status = StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let upstream_headers = upstream.headers().clone();

    // Read body with size cap and timeout
    let resp_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(forward_cfg.response_body_timeout_secs),
        upstream.bytes(),
    )
    .await
    .map_err(|_| AppError::Proxy("Upstream response body timed out".into()))?
    .map_err(|e| AppError::Proxy(format!("Failed to read upstream body: {e}")))?;

    if resp_bytes.len() > forward_cfg.max_response_body_bytes {
        return Err(AppError::Proxy("Upstream response too large".into()));
    }

    let mut response = HttpResponse::build(upstream_status);

    // Forward upstream headers, skipping hop-by-hop
    for (k, v) in &upstream_headers {
        let k_lower = k.as_str().to_lowercase();
        if HOP_BY_HOP_HEADERS.contains(&k_lower.as_str()) {
            continue;
        }
        if let Ok(converted) = actix_web::http::header::HeaderValue::from_bytes(v.as_bytes()) {
            response.insert_header((k.as_str(), converted));
        }
    }

    // Apply response header overrides from proxy_data (r_* params)
    if let Some(custom_headers) = &proxy_data.response_headers {
        for (key, value) in custom_headers
            .as_object()
            .unwrap_or(&serde_json::Map::new())
        {
            if let Some(value_str) = value.as_str() {
                response.insert_header((key.as_str(), value_str));
            }
        }
    }

    Ok(response.body(resp_bytes))
}

/// Shared URL-building logic used by generate_url and generate_encrypted_or_encoded_url.
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

pub async fn generate_url(req: web::Json<GenerateUrlRequest>) -> AppResult<HttpResponse> {
    let url = build_proxy_url(
        &req.mediaflow_proxy_url,
        req.endpoint.as_deref(),
        &req.destination_url,
        &req.query_params,
        &req.request_headers,
        &req.response_headers,
        &req.propagate_response_headers,
        &req.remove_response_headers,
        req.stream_transformer.as_deref(),
        req.filename.as_deref(),
        req.api_password.as_deref(),
        req.expiration,
        req.ip.as_deref(),
        req.base64_encode_destination,
    )?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "url": url })))
}

// Mirrors Python's IP_LOOKUP_SERVICES — tried in order; first success wins.
const IP_LOOKUP_SERVICES: &[(&str, &str)] = &[
    ("https://api.ipify.org?format=json", "ip"),
    ("https://ipinfo.io/json", "ip"),
    ("https://httpbin.org/ip", "origin"),
];

pub async fn get_public_ip(
    stream_manager: web::Data<StreamManager>,
    forward_cfg: web::Data<ForwardConfig>,
) -> AppResult<HttpResponse> {
    if let Some(ref ip) = forward_cfg.public_ip {
        return Ok(HttpResponse::Ok().json(serde_json::json!({ "ip": ip })));
    }
    for (url, key) in IP_LOOKUP_SERVICES {
        match stream_manager
            .make_request((*url).to_string(), HeaderMap::new())
            .await
        {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(data) => {
                    if let Some(ip) = data.get(*key).and_then(|v| v.as_str()) {
                        let ip = ip.trim();
                        if !ip.is_empty() {
                            return Ok(HttpResponse::Ok().json(serde_json::json!({ "ip": ip })));
                        }
                    }
                    tracing::warn!("IP lookup {} returned no '{}' field", url, key);
                }
                Err(e) => tracing::warn!("IP lookup {} body parse failed: {}", url, e),
            },
            Err(e) => tracing::warn!("IP lookup {} request failed: {}", url, e),
        }
    }

    Err(AppError::Upstream(
        "Failed to retrieve public IP from all services".to_string(),
    ))
}

// Deprecated alias — same logic as generate_url but returns {"encoded_url": ...}
pub async fn generate_encrypted_or_encoded_url(
    req: web::Json<GenerateUrlRequest>,
) -> AppResult<HttpResponse> {
    let url = build_proxy_url(
        &req.mediaflow_proxy_url,
        req.endpoint.as_deref(),
        &req.destination_url,
        &req.query_params,
        &req.request_headers,
        &req.response_headers,
        &req.propagate_response_headers,
        &req.remove_response_headers,
        req.stream_transformer.as_deref(),
        req.filename.as_deref(),
        req.api_password.as_deref(),
        req.expiration,
        req.ip.as_deref(),
        req.base64_encode_destination,
    )?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "encoded_url": url })))
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

// ---------------------------------------------------------------------------
// Base64 utilities
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct Base64Query {
    pub url: Option<String>,
    pub encoded_url: Option<String>,
}

pub async fn base64_encode(query: web::Query<Base64Query>) -> HttpResponse {
    let url = match &query.url {
        Some(u) => u.as_str(),
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "missing `url` query param"}))
        }
    };
    let encoded = encode_url_to_base64(url);
    HttpResponse::Ok().json(serde_json::json!({"encoded_url": encoded, "original_url": url}))
}

pub async fn base64_decode(query: web::Query<Base64Query>) -> HttpResponse {
    let enc = match &query.encoded_url {
        Some(e) => e.as_str(),
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "missing `encoded_url` query param"}))
        }
    };
    match decode_base64_url(enc) {
        Some(decoded) => {
            HttpResponse::Ok().json(serde_json::json!({"decoded_url": decoded, "encoded_url": enc}))
        }
        None => HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid base64 URL"})),
    }
}

pub async fn base64_check(query: web::Query<Base64Query>) -> HttpResponse {
    let url = match &query.url {
        Some(u) => u.as_str(),
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "missing `url` query param"}))
        }
    };
    let is_b64 = is_base64_url(url);
    let mut result = serde_json::json!({"url": url, "is_base64": is_b64});
    if is_b64 {
        if let Some(decoded) = decode_base64_url(url) {
            result["decoded_url"] = serde_json::Value::String(decoded);
        }
    }
    HttpResponse::Ok().json(result)
}
