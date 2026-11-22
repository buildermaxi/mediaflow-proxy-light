/// URL-format compatibility tests (the `/_token_…` path and flat query-param
/// formats of the Python mediaflow-proxy), plus the token-auth middleware.
///
/// The tokens themselves are AES-256-GCM sealed and no longer interoperate
/// with the Python proxy's AES-CBC tokens; see `src/auth/encryption.rs`.
///
/// Run:  cargo test --test compat_tests
use mediaflow_proxy_light::auth::encryption::EncryptionHandler;
use std::collections::HashMap;

const PASSWORD: &[u8] = b"test_secret";

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

fn handler() -> EncryptionHandler {
    EncryptionHandler::new(PASSWORD).unwrap()
}

/// Extract the token from a `/_token_{token}/…` or `?token={token}` URL.
fn extract_token_from_url(url: &str) -> &str {
    if let Some((_, rest)) = url.split_once("/_token_") {
        let end = rest.find('/').unwrap_or(rest.len());
        &rest[..end]
    } else if let Some(pos) = url.find("?token=") {
        &url[pos + 7..]
    } else {
        panic!("no token found in URL: {url}");
    }
}

/// Encrypted URLs must preserve path prefixes in the externally visible proxy URL.
#[test]
fn encrypted_url_preserves_proxy_base_path() {
    let url = build_proxy_url(
        "https://proxy.example.test/custom/prefix/",
        Some("/proxy/stream"),
        "https://origin.example.test/files/movie.mkv",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        None,
        None,
        Some("test_secret"),
        None,
        None,
        false,
    )
    .unwrap();

    assert!(
        url.starts_with("https://proxy.example.test/custom/prefix/_token_"),
        "encrypted URL must keep the complete proxy base path, got: {url}"
    );
    assert!(
        url.ends_with("/proxy/stream"),
        "endpoint must follow token and preserved base path, got: {url}"
    );
}

/// Parse `key=value` pairs from a URL query string (percent-decoded, `+`→space).
fn parse_qs(url: &str) -> HashMap<String, String> {
    let qs = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    qs.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| {
            let decode = |s: &str| {
                urlencoding::decode(s)
                    .unwrap_or_else(|_| s.into())
                    .replace('+', " ")
            };
            (decode(k), decode(v))
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// 2. URL generation — encrypted (/_token_ path format)
// ────────────────────────────────────────────────────────────────────────────

use mediaflow_proxy_light::proxy::handler::build_proxy_url;

fn default_headers() -> HashMap<String, String> {
    HashMap::new()
}

/// Encrypted URL must use Python's /_token_{token}{endpoint} path format.
#[test]
fn encrypted_url_uses_token_path_format() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        None,
        None,
        Some("test_secret"),
        None,
        None,
        false,
    )
    .unwrap();

    assert!(
        url.starts_with("https://proxy.example.com/_token_"),
        "encrypted URL must use /_token_ prefix, got: {url}"
    );
    assert!(
        url.ends_with("/proxy/stream"),
        "endpoint must follow token, got: {url}"
    );
    // Must NOT contain ?token=
    assert!(
        !url.contains("?token="),
        "must not use query-param token style"
    );
}

/// The token embedded in the /_token_ URL must be decryptable back to the original payload.
#[test]
fn encrypted_url_token_is_valid_and_decryptable() {
    let dest = "https://cdn.example.com/stream.m3u8";
    let mut req_hdrs = HashMap::new();
    req_hdrs.insert("Authorization".into(), "Bearer tok".into());

    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        dest,
        &default_headers(),
        &req_hdrs,
        &default_headers(),
        &default_headers(),
        &[],
        None,
        None,
        Some("test_secret"),
        None,
        None,
        false,
    )
    .unwrap();

    let token = extract_token_from_url(&url);
    let pd = handler().decrypt(token, None).unwrap();
    assert_eq!(pd.destination, dest);
    let rh = pd.request_headers.unwrap();
    assert_eq!(rh["Authorization"].as_str().unwrap(), "Bearer tok");
}

/// The token is bound to the endpoint it was generated for.
#[test]
fn encrypted_url_token_is_bound_to_its_endpoint() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/movie.mkv",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        None,
        Some("movie.mkv"),
        Some("test_secret"),
        None,
        None,
        false,
    )
    .unwrap();
    let token = extract_token_from_url(&url);
    let pd = handler().decrypt(token, None).unwrap();
    assert_eq!(pd.endpoint.as_deref(), Some("/proxy/stream"));
    assert!(handler()
        .authorize(token, None, "/proxy/stream/movie.mkv")
        .is_ok());
    assert!(handler().authorize(token, None, "/proxy/ip").is_err());
}

/// An encrypted URL without an endpoint would authorize nothing, so it is
/// refused at generation time rather than handed out broken.
#[test]
fn encrypted_url_requires_an_endpoint() {
    for endpoint in [None, Some(""), Some("/"), Some("///")] {
        let result = build_proxy_url(
            "https://proxy.example.com",
            endpoint,
            "https://cdn.example.com/movie.mkv",
            &default_headers(),
            &default_headers(),
            &default_headers(),
            &default_headers(),
            &[],
            None,
            None,
            Some("test_secret"),
            None,
            None,
            false,
        );
        assert!(result.is_err(), "endpoint {endpoint:?} must be refused");
    }
}

/// Inputs that could only produce a token the server then refuses are
/// rejected when generating the URL.
#[test]
fn encrypted_url_refuses_unusable_inputs() {
    let build = |dest: &str, ip: Option<&str>| {
        build_proxy_url(
            "https://proxy.example.com",
            Some("/proxy/stream"),
            dest,
            &default_headers(),
            &default_headers(),
            &default_headers(),
            &default_headers(),
            &[],
            None,
            None,
            Some("test_secret"),
            None,
            ip,
            false,
        )
    };
    assert!(build("", None).is_err(), "empty destination");
    assert!(
        build("https://cdn.example.com/a.mkv", Some("nope")).is_err(),
        "bad ip"
    );
    // An empty ip means "not bound".
    let url = build("https://cdn.example.com/a.mkv", Some("")).unwrap();
    let pd = handler()
        .decrypt(extract_token_from_url(&url), None)
        .unwrap();
    assert_eq!(pd.ip, None);
}

/// A trailing slash on the endpoint doesn't produce `//` before the filename.
#[test]
fn encrypted_url_trailing_slash_endpoint() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream/"),
        "https://cdn.example.com/movie.mkv",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        None,
        Some("movie.mkv"),
        Some("test_secret"),
        None,
        None,
        false,
    )
    .unwrap();
    assert!(url.ends_with("/proxy/stream/movie.mkv"), "got: {url}");
    let (_, after_token) = url.split_once("/_token_").unwrap();
    assert!(!after_token.contains("//"), "got: {url}");
}

/// Filename is appended after the endpoint path, not before the token.
#[test]
fn encrypted_url_filename_after_endpoint() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        None,
        Some("video.m3u8"),
        Some("test_secret"),
        None,
        None,
        false,
    )
    .unwrap();

    // Format: https://proxy.example.com/_token_{tok}/proxy/stream/video.m3u8
    assert!(url.ends_with("/proxy/stream/video.m3u8"), "got: {url}");
    let token = extract_token_from_url(&url);
    // token must still decrypt correctly (filename is NOT in the token)
    let pd = handler().decrypt(token, None).unwrap();
    assert_eq!(pd.destination, "https://cdn.example.com/stream.m3u8");
}

/// Expiration is embedded in the token and honoured on decrypt.
#[test]
fn encrypted_url_expiration_in_token() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        None,
        None,
        Some("test_secret"),
        Some(3600), // 1 hour from now
        None,
        false,
    )
    .unwrap();

    let token = extract_token_from_url(&url);
    let pd = handler().decrypt(token, None).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp = pd.exp.unwrap();
    assert!(exp > now, "exp {exp} must be in the future (now={now})");
    assert!(exp <= now + 3601, "exp must be ~1 hour from now");
}

/// IP binding: token carries the ip and middleware enforces it.
#[test]
fn encrypted_url_ip_binding_in_token() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        None,
        None,
        Some("test_secret"),
        None,
        Some("1.2.3.4"),
        false,
    )
    .unwrap();

    let token = extract_token_from_url(&url);
    assert!(handler().decrypt(token, Some("1.2.3.4")).is_ok());
    assert!(handler().decrypt(token, Some("9.9.9.9")).is_err());
}

// ────────────────────────────────────────────────────────────────────────────
// 3. URL generation — unencrypted (flat query params)
// ────────────────────────────────────────────────────────────────────────────

/// Unencrypted URL must use ?d=... query param style (no /_token_).
#[test]
fn unencrypted_url_uses_query_param_style() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        None,
        None,
        None, // no api_password
        None,
        None,
        false,
    )
    .unwrap();

    assert!(
        url.starts_with("https://proxy.example.com/proxy/stream?"),
        "got: {url}"
    );
    assert!(!url.contains("/_token_"), "must not use token path format");
    let qs = parse_qs(&url);
    assert_eq!(qs["d"], "https://cdn.example.com/stream.m3u8");
}

/// Request headers get h_ prefix; response headers get r_ prefix.
#[test]
fn unencrypted_url_header_prefixes() {
    let mut req_hdrs = HashMap::new();
    req_hdrs.insert("Authorization".into(), "Bearer tok".into());
    let mut resp_hdrs = HashMap::new();
    resp_hdrs.insert("Content-Type".into(), "video/mp4".into());

    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &req_hdrs,
        &resp_hdrs,
        &default_headers(),
        &[],
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .unwrap();

    let qs = parse_qs(&url);
    assert_eq!(
        qs["h_Authorization"], "Bearer tok",
        "request header needs h_ prefix"
    );
    assert_eq!(
        qs["r_Content-Type"], "video/mp4",
        "response header needs r_ prefix"
    );
}

/// range and if-range request headers must be excluded (they are per-request dynamic values).
/// Python does the same: SUPPORTED_REQUEST_HEADERS are filtered out.
#[test]
fn unencrypted_url_skips_supported_request_headers() {
    let mut req_hdrs = HashMap::new();
    req_hdrs.insert("Authorization".into(), "Bearer tok".into());
    req_hdrs.insert("range".into(), "bytes=0-".into()); // must be excluded
    req_hdrs.insert("if-range".into(), "etag123".into()); // must be excluded

    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &req_hdrs,
        &default_headers(),
        &default_headers(),
        &[],
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .unwrap();

    let qs = parse_qs(&url);
    assert!(
        qs.contains_key("h_Authorization"),
        "Authorization must be present"
    );
    assert!(!qs.contains_key("h_range"), "range must be filtered out");
    assert!(
        !qs.contains_key("h_if-range"),
        "if-range must be filtered out"
    );
    assert!(
        !qs.contains_key("range"),
        "range must not appear without prefix either"
    );
}

/// Propagate headers get rp_ prefix.
#[test]
fn unencrypted_url_propagate_headers_rp_prefix() {
    let mut prop = HashMap::new();
    prop.insert("Cache-Control".into(), "no-cache".into());

    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &prop,
        &[],
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .unwrap();

    let qs = parse_qs(&url);
    assert_eq!(
        qs["rp_Cache-Control"], "no-cache",
        "propagate header needs rp_ prefix"
    );
}

/// remove_response_headers serialises as x_headers=A,B.
#[test]
fn unencrypted_url_remove_headers_x_headers_param() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &["X-Frame-Options".into(), "X-XSS-Protection".into()],
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .unwrap();

    let qs = parse_qs(&url);
    let x = qs["x_headers"].as_str();
    // Order from Vec<String> is deterministic (insertion order)
    assert!(
        x.contains("X-Frame-Options") && x.contains("X-XSS-Protection"),
        "x_headers must list both headers, got: {x}"
    );
}

/// stream_transformer serialises as transformer=<id>.
#[test]
fn unencrypted_url_stream_transformer_param() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        Some("tsfix"),
        None,
        None,
        None,
        None,
        false,
    )
    .unwrap();

    let qs = parse_qs(&url);
    assert_eq!(qs["transformer"], "tsfix");
}

/// filename is appended to the path before the query string (like Python).
#[test]
fn unencrypted_url_filename_in_path() {
    let url = build_proxy_url(
        "https://proxy.example.com",
        Some("/proxy/stream"),
        "https://cdn.example.com/stream.m3u8",
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &default_headers(),
        &[],
        None,
        Some("video.m3u8"),
        None,
        None,
        None,
        false,
    )
    .unwrap();

    // Path must include filename before the ?
    let path = url.split('?').next().unwrap();
    assert!(
        path.ends_with("/proxy/stream/video.m3u8"),
        "filename must be appended to path, got path: {path}"
    );
    // d= must still be in query string
    let qs = parse_qs(&url);
    assert!(qs.contains_key("d"));
}

// ────────────────────────────────────────────────────────────────────────────
// 5. Middleware /_token_ path extraction — via actix-web test client
//
// Notes on test strategy:
//  a) Auth rejection propagates as an actix-web `Error`, which the real HTTP
//     dispatcher turns into a 401 via `AppError`'s `ResponseError` impl.
//     `test::call_service` panics on `Err(...)`, so rejection tests use
//     `test::try_call_service` and render the error the same way.
//
//  b) actix-web's route matching reads the URI from `req.head().uri` at the
//     time the *router* service is called.  Because `AuthMiddleware::call`
//     rewrites `req.head_mut().uri` before forwarding to the inner service,
//     the router sees the stripped path.  We verify this with a
//     `default_service` echo handler rather than an exact-path route, which
//     avoids a dependency on actix-web's internal route-caching behaviour.
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod middleware_tests {
    use actix_web::{test, web, App, HttpRequest, HttpResponse};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use mediaflow_proxy_light::auth::encryption::{EncryptionHandler, ProxyData};
    use mediaflow_proxy_light::auth::middleware::AuthMiddleware;

    fn make_token(password: &str, dest: &str) -> String {
        let h = EncryptionHandler::new(password.as_bytes()).unwrap();
        let pd = ProxyData {
            destination: dest.into(),
            endpoint: Some("/proxy/stream".into()),
            ..Default::default()
        };
        h.encrypt(&pd).unwrap()
    }

    fn seal(password: &str, pd: ProxyData) -> String {
        EncryptionHandler::new(password.as_bytes())
            .unwrap()
            .encrypt(&pd)
            .unwrap()
    }

    fn stream_pd() -> ProxyData {
        ProxyData {
            destination: "https://cdn.example.com/stream.m3u8".into(),
            endpoint: Some("/proxy/stream".into()),
            ..Default::default()
        }
    }

    /// Status, all response headers (sorted) and body.
    type Outcome = (u16, Vec<(String, String)>, String);

    /// Runs `uri` through the middleware (password "secret") and returns what
    /// the client would receive, rendering a rejection the way the HTTP
    /// dispatcher would.
    async fn respond(uri: &str, headers: &[(&str, &str)]) -> Outcome {
        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("secret".into()))
                .default_service(web::to(echo_path)),
        )
        .await;
        let mut req = test::TestRequest::get().uri(uri);
        for &(name, value) in headers {
            req = req.insert_header((name, value));
        }
        let resp = match test::try_call_service(&app, req.to_request()).await {
            Ok(resp) => resp.into_parts().1.map_into_boxed_body(),
            Err(err) => err.error_response(),
        };
        let status = resp.status().as_u16();
        let mut header_list: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        header_list.sort();
        let body = actix_web::body::to_bytes(resp.into_body())
            .await
            .unwrap_or_default();
        (
            status,
            header_list,
            String::from_utf8_lossy(&body).into_owned(),
        )
    }

    async fn status_and_body(uri: &str) -> (u16, String) {
        let (status, _, body) = respond(uri, &[]).await;
        (status, body)
    }

    /// Returns 200 with the request path as body — lets us verify URI rewriting.
    async fn echo_path(req: HttpRequest) -> HttpResponse {
        HttpResponse::Ok().body(req.path().to_string())
    }

    // ── 5a. /_token_ path token: auth accepted, path rewritten ───────────────

    #[actix_web::test]
    async fn path_token_accepted() {
        let token = make_token("secret", "https://cdn.example.com/stream.m3u8");
        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("secret".into()))
                .default_service(web::to(echo_path)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/_token_{}/proxy/stream", token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "/_token_ path token must be accepted");
    }

    #[actix_web::test]
    async fn path_token_uri_is_rewritten_to_endpoint() {
        // After stripping /_token_{token}, the handler must see /proxy/stream.
        let token = make_token("secret", "https://cdn.example.com/stream.m3u8");
        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("secret".into()))
                .default_service(web::to(echo_path)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/_token_{}/proxy/stream", token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body = test::read_body(resp).await;
        assert_eq!(
            body,
            "/proxy/stream",
            "middleware must strip /_token_ prefix; handler saw: {}",
            String::from_utf8_lossy(&body)
        );
    }

    #[actix_web::test]
    async fn path_token_with_filename_uri_rewritten() {
        let token = make_token("secret", "https://cdn.example.com/stream.m3u8");
        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("secret".into()))
                .default_service(web::to(echo_path)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/_token_{}/proxy/stream/video.m3u8", token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body = test::read_body(resp).await;
        assert_eq!(
            body,
            "/proxy/stream/video.m3u8",
            "filename must be preserved after rewrite; handler saw: {}",
            String::from_utf8_lossy(&body)
        );
    }

    // ── 5b. ?token= query-param token still works ────────────────────────────

    #[actix_web::test]
    async fn query_token_accepted() {
        let token = make_token("secret", "https://cdn.example.com/stream.m3u8");
        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("secret".into()))
                .default_service(web::to(echo_path)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/proxy/stream?token={}", token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "?token= query param must be accepted");

        // Path must NOT be rewritten for query-param token style
        let body = test::read_body(resp).await;
        assert_eq!(body, "/proxy/stream");
    }

    // ── 5c. ?api_password= direct auth still works ───────────────────────────

    #[actix_web::test]
    async fn direct_api_password_accepted() {
        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("secret".into()))
                .default_service(web::to(echo_path)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/proxy/stream?api_password=secret&d=https://cdn.example.com/stream.m3u8")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "?api_password= must be accepted");
    }

    // ── 5d. No password configured → allow everything but tokens ─────────────

    /// Without a password there is no key: tokens get an explicit 401 that
    /// points at the misconfiguration, whichever way they are sent.
    #[actix_web::test]
    async fn no_password_configured_refuses_tokens() {
        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("".into()))
                .default_service(web::to(echo_path)),
        )
        .await;
        for uri in [
            "/_token_AAAA/proxy/stream",
            "/proxy/stream?token=AAAA",
            "/proxy/stream?token=",
        ] {
            let err = test::try_call_service(&app, test::TestRequest::get().uri(uri).to_request())
                .await
                .err()
                .unwrap_or_else(|| panic!("{uri} must be refused"));
            let resp = err.error_response();
            assert_eq!(resp.status().as_u16(), 401, "{uri}");
            let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
            assert!(
                String::from_utf8_lossy(&body).contains("no api_password configured"),
                "{uri}"
            );
        }
    }

    #[actix_web::test]
    async fn no_password_configured_allows_all() {
        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("".into()))
                .default_service(web::to(echo_path)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/proxy/stream?d=https://cdn.example.com/stream.m3u8")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "no password → allow all");
    }

    // ── 5e. Auth rejection — tested via decrypt() unit tests (section 1 above)
    //        because test::call_service panics when the service returns Err.
    //        The real HTTP dispatcher converts the Err to a 401 response via
    //        AppError's ResponseError impl (see src/error.rs).

    /// Confirms that a wrong-password token is rejected at the decrypt layer.
    #[actix_web::test]
    async fn wrong_password_token_decrypt_rejected() {
        let good = EncryptionHandler::new(b"secret").unwrap();
        let bad = EncryptionHandler::new(b"wrong").unwrap();
        let pd = ProxyData {
            destination: "https://cdn.example.com/stream.m3u8".into(),
            endpoint: Some("/proxy/stream".into()),
            ..Default::default()
        };
        let token = bad.encrypt(&pd).unwrap();
        // The "secret" handler must reject a token produced by "wrong"
        assert!(
            good.decrypt(&token, None).is_err(),
            "wrong-password token must be rejected"
        );
    }

    // ── 5f. Rejections over HTTP: one indistinguishable 401 ────────────────

    const GENERIC_401: &str = r#"{"error":"Invalid or expired token"}"#;

    /// Every way a token can be refused looks exactly the same to the
    /// client: status, headers and body.
    #[actix_web::test]
    async fn every_token_rejection_is_identical_over_http() {
        let token = seal("secret", stream_pd());
        let mut tampered = token.clone().into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        raw[0] = raw[0].wrapping_add(1);
        let other_version = URL_SAFE_NO_PAD.encode(&raw);
        let other_key = seal("other", stream_pd());
        let expired = seal(
            "secret",
            ProxyData {
                exp: Some(1),
                ..stream_pd()
            },
        );
        let bound = seal(
            "secret",
            ProxyData {
                ip: Some("1.2.3.4".into()),
                ..stream_pd()
            },
        );
        let no_destination = seal(
            "secret",
            ProxyData {
                destination: String::new(),
                ..stream_pd()
            },
        );
        // Python-era AES-CBC token (password "test_secret").
        let legacy = "AAECAwQFBgcICQoLDA0OD1NDNLU6BmO_093POOmfhHoL29QQVC_7Zf3ZkxMIV0AmCCVw7DPCWWcA59PdeoN7PQ";

        type Case<'a> = (&'a str, String, Vec<(&'a str, &'a str)>);
        let cases: Vec<Case> = vec![
            (
                "tampered path",
                format!("/_token_{tampered}/proxy/stream"),
                vec![],
            ),
            (
                "tampered query",
                format!("/proxy/stream?token={tampered}"),
                vec![],
            ),
            (
                "other version",
                format!("/_token_{other_version}/proxy/stream"),
                vec![],
            ),
            (
                "other key",
                format!("/_token_{other_key}/proxy/stream"),
                vec![],
            ),
            (
                "legacy cbc",
                format!("/_token_{legacy}/proxy/stream"),
                vec![],
            ),
            ("garbage", "/_token_AAAA/proxy/stream".into(), vec![]),
            ("not base64", "/_token_%21%21/proxy/stream".into(), vec![]),
            ("empty path token", "/_token_/proxy/stream".into(), vec![]),
            ("empty query token", "/proxy/stream?token=".into(), vec![]),
            ("expired", format!("/_token_{expired}/proxy/stream"), vec![]),
            (
                "other ip",
                format!("/_token_{bound}/proxy/stream"),
                vec![("x-forwarded-for", "9.9.9.9")],
            ),
            (
                "unknown ip",
                format!("/_token_{bound}/proxy/stream"),
                vec![],
            ),
            (
                "no destination",
                format!("/_token_{no_destination}/proxy/stream"),
                vec![],
            ),
            (
                "other endpoint",
                format!("/_token_{token}/proxy/ip"),
                vec![],
            ),
            (
                "dot segment",
                format!("/_token_{token}/proxy/stream/../ip"),
                vec![],
            ),
            (
                "double slash",
                format!("/_token_{token}//proxy/stream"),
                vec![],
            ),
            (
                "with origin",
                format!("/_token_{tampered}/proxy/stream"),
                vec![("origin", "https://evil.example")],
            ),
        ];

        let reference = respond(&cases[0].1, &cases[0].2).await;
        assert_eq!(reference.0, 401);
        assert_eq!(reference.2, GENERIC_401);
        for (case, uri, headers) in &cases {
            assert_eq!(&respond(uri, headers).await, &reference, "{case}");
        }

        // The same IP-bound token is accepted from its own address.
        let (status, _, _) = respond(
            &format!("/_token_{bound}/proxy/stream"),
            &[("x-forwarded-for", "1.2.3.4")],
        )
        .await;
        assert_eq!(status, 200);
    }

    #[actix_web::test]
    async fn query_token_accepted_with_a_filename() {
        let token = seal("secret", stream_pd());
        assert_eq!(
            status_and_body(&format!("/proxy/stream/movie.mkv?token={token}")).await,
            (200, "/proxy/stream/movie.mkv".to_string())
        );
    }

    #[actix_web::test]
    async fn stream_token_is_refused_on_other_endpoints() {
        let token = make_token("secret", "https://cdn.example.com/stream.m3u8");
        for path in [
            "/proxy/ip",
            "/dashboard/stats",
            "/generate_urls",
            "/",
            "/proxy/streamx",
        ] {
            assert_eq!(
                status_and_body(&format!("/_token_{token}{path}")).await,
                (401, GENERIC_401.to_string()),
                "/_token_…{path}"
            );
        }
        // Spelled differently from the endpoint it was minted for.
        assert_eq!(
            status_and_body(&format!("/_token_{token}/proxy/%73tream")).await,
            (401, GENERIC_401.to_string())
        );
        // No path after the token at all.
        assert_eq!(
            status_and_body(&format!("/_token_{token}")).await,
            (401, GENERIC_401.to_string())
        );
        // Query-param style is held to the same rule.
        assert_eq!(
            status_and_body(&format!("/proxy/ip?token={token}")).await,
            (401, GENERIC_401.to_string())
        );
    }

    /// Decrypted query_params must be injected back into the request's query
    /// string so handlers can read them via req.query_string(), as in the
    /// Python proxy.
    #[actix_web::test]
    async fn token_query_params_injected_into_query_string() {
        use mediaflow_proxy_light::auth::encryption::ProxyData;

        let h = EncryptionHandler::new(b"secret").unwrap();
        let mut extra = std::collections::HashMap::new();
        extra.insert("extra".to_string(), serde_json::json!("kept"));
        let pd = ProxyData {
            destination: "https://example.com/movie.mkv".into(),
            query_params: Some(serde_json::Value::Object(extra.into_iter().collect())),
            endpoint: Some("/proxy/stream".into()),
            ..Default::default()
        };
        let token = h.encrypt(&pd).unwrap();

        async fn echo_query(req: HttpRequest) -> HttpResponse {
            HttpResponse::Ok().body(req.query_string().to_string())
        }

        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("secret".into()))
                .service(web::scope("/proxy").route("/stream", web::get().to(echo_query))),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/_token_{}/proxy/stream", token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(
            body.contains("extra=kept"),
            "decrypted param must be in query string, got: {body}"
        );
        assert!(
            body.contains("d=https"),
            "destination must appear as d= param, got: {body}"
        );
    }

    /// After middleware rewrites /_token_{t}/proxy/stream → /proxy/stream,
    /// the actix-web router must still match the /proxy scope's /stream route.
    /// This guards against the 404 regression where URI rewriting worked but
    /// the scoped route wasn't reached.
    #[actix_web::test]
    async fn token_path_routes_to_proxy_stream_scope() {
        use actix_web::web::ReqData;
        use mediaflow_proxy_light::auth::encryption::ProxyData;

        let token = make_token("secret", "https://cdn.example.com/stream.m3u8");

        async fn proxy_stream_stub(proxy_data: ReqData<ProxyData>) -> HttpResponse {
            HttpResponse::Ok().body(proxy_data.destination.clone())
        }

        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new("secret".into()))
                .service(
                    web::scope("/proxy")
                        .route("/stream", web::get().to(proxy_stream_stub))
                        .route("/stream/{filename:.*}", web::get().to(proxy_stream_stub)),
                ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/_token_{}/proxy/stream", token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            200,
            "/_token_/proxy/stream must route to the /proxy scope handler, not 404"
        );
        let body = test::read_body(resp).await;
        assert_eq!(
            body, "https://cdn.example.com/stream.m3u8",
            "ProxyData.destination must flow through to the handler"
        );
    }
}
