use actix_web::HttpMessage;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::Arc;

use crate::auth::encryption::EncryptionHandler;
use crate::auth::session::password_matches;
use crate::error::AppError;

/// Routes that authenticate themselves, so the middleware lets them through:
/// the dashboard routes check the session cookie (see `auth::session`).
const OPEN_ENDPOINTS: &[&str] = &[
    "/health",
    "/",
    "/login",
    "/logout",
    "/dashboard/stats",
    "/dashboard/history",
];

/// The only route that takes the API password itself (`?api_password=…`).
/// Streams are only reachable with a `/_token_…/` prefix.
const PASSWORD_ENDPOINT: &str = "/proxy/ip";

/// Path prefix carrying an encrypted token: `/_token_{token}/{endpoint}`.
const TOKEN_PREFIX: &str = "/_token_";

#[derive(Clone)]
pub struct AuthMiddleware {
    encryption_handler: Arc<EncryptionHandler>,
    api_password: Arc<String>,
}

impl AuthMiddleware {
    /// `token_ttl` caps how far in the future a token's expiry may be
    /// (`0` = no cap); see [`EncryptionHandler::with_max_lifetime`].
    pub fn new(api_password: String, token_ttl: u64) -> Self {
        let encryption_handler = EncryptionHandler::new(api_password.as_bytes())
            .expect("Failed to create encryption handler")
            .with_max_lifetime(token_ttl);
        Self {
            encryption_handler: Arc::new(encryption_handler),
            api_password: Arc::new(api_password),
        }
    }
}

/// The `api_password` query parameter, form-decoded (`%XX` and `+` for a
/// space, as `URLSearchParams` writes it).
fn query_password(query_string: &str) -> Option<String> {
    url::form_urlencoded::parse(query_string.as_bytes())
        .find(|(key, _)| key == "api_password")
        .map(|(_, value)| value.into_owned())
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
    encryption_handler: Arc<EncryptionHandler>,
    api_password: Arc<String>,
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
            // Path token: /_token_{token}/{endpoint}
            let path = req.path().to_owned();
            if let Some(after_marker) = path.strip_prefix(TOKEN_PREFIX) {
                let (token, remaining_path) = match after_marker.find('/') {
                    Some(pos) => (&after_marker[..pos], &after_marker[pos..]),
                    None => (after_marker, "/"),
                };
                // The token must open *and* have been minted for the
                // endpoint this request is for.
                let proxy_data = encryption_handler
                    .authorize(token, remaining_path)
                    .map_err(Error::from)?;
                // Route the request to the endpoint, without any query
                // string: everything a stream needs is in the token, and
                // nothing the client appends may add to it.
                let new_uri: actix_web::http::Uri = remaining_path.parse().map_err(|_| {
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

            if OPEN_ENDPOINTS.contains(&req.path()) {
                return service.call(req).await;
            }

            if req.path() == PASSWORD_ENDPOINT {
                let given = query_password(req.query_string());
                // Constant time, and never true for an empty configured password.
                if given.is_some_and(|given| password_matches(&given, &api_password)) {
                    return service.call(req).await;
                }
            }

            Err(AppError::Auth("Invalid or missing authentication".to_string()).into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_api_password_parameter() {
        assert_eq!(
            query_password("a=1&api_password=p%40ss&b=2").as_deref(),
            Some("p@ss")
        );
        // `URLSearchParams` writes a space as `+`.
        assert_eq!(
            query_password("api_password=a+b%20c").as_deref(),
            Some("a b c")
        );
        assert_eq!(query_password("api_password_x=1"), None);
        assert_eq!(query_password(""), None);
    }

    #[test]
    fn an_empty_configured_password_matches_nothing() {
        assert!(password_matches("secret", "secret"));
        assert!(!password_matches("", ""));
        assert!(!password_matches("secret", "secret-longer"));
    }
}
