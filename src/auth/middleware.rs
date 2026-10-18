use actix_web::HttpMessage;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures::future::LocalBoxFuture;
use serde_json::Value;
use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::Arc;

use crate::auth::encryption::{EncryptionHandler, ProxyData};
use crate::error::AppError;

/// Routes that authenticate themselves, so the middleware lets them through:
/// - `/generate_urls` reads `api_password` from its JSON body (and works
///   without one for unencrypted URLs, as AIOStreams expects);
/// - the dashboard routes check the session cookie (see `auth::session`).
const OPEN_ENDPOINTS: &[&str] = &[
    "/generate_urls",
    "/health",
    "/",
    "/login",
    "/logout",
    "/dashboard/stats",
    "/dashboard/history",
];

#[derive(Clone)]
pub struct AuthMiddleware {
    encryption_handler: Option<Arc<EncryptionHandler>>,
    api_password: String,
}

impl AuthMiddleware {
    pub fn new(api_password: String) -> Self {
        let encryption_handler = if !api_password.is_empty() {
            Some(Arc::new(
                EncryptionHandler::new(api_password.as_bytes())
                    .expect("Failed to create encryption handler"),
            ))
        } else {
            None
        };

        Self {
            encryption_handler,
            api_password,
        }
    }

    fn extract_query_params(query_string: &str) -> serde_json::Map<String, Value> {
        let mut params = serde_json::Map::new();
        for pair in query_string.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if !key.is_empty() && !value.is_empty() {
                    params.insert(
                        key.to_string(),
                        Value::String(
                            urlencoding::decode(value)
                                .unwrap_or_else(|_| value.into())
                                .into_owned(),
                        ),
                    );
                }
            }
        }
        params
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Rc::new(service),
            encryption_handler: self.encryption_handler.clone(),
            api_password: self.api_password.clone(),
        }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: Rc<S>,
    encryption_handler: Option<Arc<EncryptionHandler>>,
    api_password: String,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let encryption_handler = self.encryption_handler.clone();
        let api_password = self.api_password.clone();

        Box::pin(async move {
            // No-auth mode: operator hasn't set `APP__AUTH__API_PASSWORD`.
            // Don't silently pass through — handlers extract ReqData<ProxyData>
            // and hard-500 with a cryptic "Missing expected request extension
            // data" message if we don't populate it here.
            if api_password.is_empty() {
                let has_path_token = req.path().starts_with("/_token_");
                let query_string = req.query_string().to_owned();
                let query_params = AuthMiddleware::extract_query_params(&query_string);

                // If the caller sent an encrypted token (path- or query-style),
                // they expect auth but the server has none configured. Surface
                // that as an explicit, actionable 401 so the operator spots the
                // misconfig from the response body instead of chasing silent
                // 500s caused by missing ProxyData in the handler extractor.
                if has_path_token || query_params.contains_key("token") {
                    return Err(AppError::Auth(
                        "Server has no api_password configured but request carries an \
                         encrypted token. Set APP__AUTH__API_PASSWORD on the server to \
                         the same value used to mint the token."
                            .to_string(),
                    )
                    .into());
                }

                // Populate ProxyData from query params (d=, h_*, r_*) so
                // handlers have a valid destination / header map to work with.
                let proxy_data = build_proxy_data_from_query(&query_params);
                req.extensions_mut().insert(proxy_data);
                return service.call(req).await;
            }

            // Check for Python-style path token: /_token_{encrypted_token}/endpoint
            let path = req.path().to_owned();
            if let Some(after_marker) = path.strip_prefix("/_token_") {
                if let Some(handler) = &encryption_handler {
                    let (token, remaining_path) = match after_marker.find('/') {
                        Some(pos) => (&after_marker[..pos], &after_marker[pos..]),
                        None => (after_marker, "/"),
                    };

                    let client_ip = req
                        .connection_info()
                        .realip_remote_addr()
                        .map(|s| s.to_string());
                    let proxy_data = handler
                        .decrypt(token, client_ip.as_deref())
                        .map_err(Error::from)?;

                    // Rewrite the URI: strip the /_token_ prefix and reconstruct the
                    // query string from the decrypted ProxyData so every handler can
                    // read d=, host=, h_*, r_* etc. from req.query_string() as normal.
                    let existing_qs = req.query_string().to_owned();
                    let qs = build_query_from_proxy_data(&proxy_data, &existing_qs);
                    let new_pq = if qs.is_empty() {
                        remaining_path.to_string()
                    } else {
                        format!("{}?{}", remaining_path, qs)
                    };
                    let new_uri: actix_web::http::Uri = new_pq.parse().map_err(|_| {
                        Error::from(AppError::Internal(
                            "Failed to rewrite request URI after token extraction".to_string(),
                        ))
                    })?;
                    // Update the HTTP head URI (read by HttpRequest::path() in handlers)
                    req.head_mut().uri = new_uri.clone();
                    // Update the routing path (read by ServiceRequest::path() for scope
                    // prefix matching — this is a separate field from the head URI and
                    // must be kept in sync, otherwise web::scope("/proxy") won't match
                    // after the rewrite).
                    req.match_info_mut().get_mut().update(&new_uri);

                    req.extensions_mut().insert(proxy_data);
                    return service.call(req).await;
                }
            }

            if OPEN_ENDPOINTS.contains(&req.path()) {
                return service.call(req).await;
            }

            let query_string = req.query_string().to_owned();
            let query_params = AuthMiddleware::extract_query_params(&query_string);

            // Check for query-param token (?token=...)
            // Successful decryption proves knowledge of api_password — the AES key is
            // derived from it, so a wrong key yields a padding error or non-JSON garbage.
            if let Some(token) = query_params.get("token").and_then(|v| v.as_str()) {
                if let Some(handler) = encryption_handler {
                    let client_ip = req
                        .connection_info()
                        .realip_remote_addr()
                        .map(|s| s.to_string());
                    let proxy_data = handler
                        .decrypt(token, client_ip.as_deref())
                        .map_err(Error::from)?;

                    // Rewrite the query string: replace ?token=... with the decrypted params
                    // so handlers read d=, host=, h_* etc. from req.query_string() as normal.
                    let qs = build_query_from_proxy_data(&proxy_data, "");
                    let base_path = req.path().to_owned();
                    let new_pq = if qs.is_empty() {
                        base_path
                    } else {
                        format!("{}?{}", base_path, qs)
                    };
                    if let Ok(new_uri) = new_pq.parse::<actix_web::http::Uri>() {
                        req.head_mut().uri = new_uri.clone();
                        req.match_info_mut().get_mut().update(&new_uri);
                    }

                    req.extensions_mut().insert(proxy_data);
                    return service.call(req).await;
                }
            }

            // Check for direct API password
            if let Some(password) = query_params.get("api_password").and_then(|v| v.as_str()) {
                if password == api_password {
                    let proxy_data = build_proxy_data_from_query(&query_params);
                    req.extensions_mut().insert(proxy_data);
                    return service.call(req).await;
                }
            }

            Err(AppError::Auth("Invalid or missing authentication".to_string()).into())
        })
    }
}

/// Build `ProxyData` from direct query-string params (`d=` or `url=` for the
/// destination, `h_*` for request headers, `r_*` for response headers).
///
/// Used by both the direct-api_password branch and the no-auth passthrough
/// branch of the middleware. Endpoints like /proxy/ip have no `d=` param, so
/// destination falls back to an empty string rather than panicking —
/// `ReqData<ProxyData>` extraction never fails.
fn build_proxy_data_from_query(query_params: &serde_json::Map<String, Value>) -> ProxyData {
    let destination = query_params
        .get("d")
        .or_else(|| query_params.get("url"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut request_headers = serde_json::Map::new();
    let mut response_headers = serde_json::Map::new();
    for (k, v) in query_params {
        if let Some(stripped) = k.strip_prefix("h_") {
            request_headers.insert(stripped.to_string(), v.clone());
        } else if let Some(stripped) = k.strip_prefix("r_") {
            response_headers.insert(stripped.to_string(), v.clone());
        }
    }

    ProxyData {
        destination,
        query_params: Some(Value::Object(query_params.clone())),
        request_headers: Some(Value::Object(request_headers)),
        response_headers: Some(Value::Object(response_headers)),
        exp: None,
        ip: None,
    }
}

/// Reconstruct a query string from a decrypted `ProxyData` so every handler
/// can read `d=`, `host=`, `h_*`, `r_*` etc. from `req.query_string()` as if
/// the params had never been encrypted.
///
/// - `existing_qs`: any query params already in the URL (other than `token=`)
///   are preserved; decrypted params take precedence on collision.
fn build_query_from_proxy_data(proxy_data: &ProxyData, existing_qs: &str) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();

    // Keep existing query params (but never re-add the token itself)
    if !existing_qs.is_empty() {
        for segment in existing_qs.split('&') {
            if let Some((k, v)) = segment.split_once('=') {
                if k != "token" && k != "api_password" {
                    let decoded = urlencoding::decode(v)
                        .unwrap_or_else(|_| v.into())
                        .into_owned();
                    pairs.push((k.to_string(), decoded));
                }
            }
        }
    }

    // Destination URL → d=
    if !proxy_data.destination.is_empty() {
        pairs.push(("d".to_string(), proxy_data.destination.clone()));
    }

    // Extra query params (e.g. host=, redirect_stream=, key_only_proxy=)
    if let Some(Value::Object(qp)) = &proxy_data.query_params {
        for (k, v) in qp {
            if let Some(s) = v.as_str() {
                pairs.push((k.clone(), s.to_string()));
            }
        }
    }

    // Request headers → h_<name>=
    if let Some(Value::Object(rh)) = &proxy_data.request_headers {
        for (k, v) in rh {
            if let Some(s) = v.as_str() {
                pairs.push((format!("h_{k}"), s.to_string()));
            }
        }
    }

    // Response headers → r_<name>=
    if let Some(Value::Object(rh)) = &proxy_data.response_headers {
        for (k, v) in rh {
            if let Some(s) = v.as_str() {
                pairs.push((format!("r_{k}"), s.to_string()));
            }
        }
    }

    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
