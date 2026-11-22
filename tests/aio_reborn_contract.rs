//! Contract with AIO Reborn, the only client: it mints the stream tokens
//! itself (in its Cloudflare Worker, `src/mediaflow/token.ts`) with the API
//! password, and builds `<base>/_token_<token>/proxy/stream[/<file>]` URLs.
//! It also reads `/proxy/ip?api_password=…`. Nothing else is reachable.
//!
//! Run:  cargo test --test aio_reborn_contract

use actix_web::{test, web, App, HttpRequest, HttpResponse};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mediaflow_proxy_light::auth::encryption::{unix_now, EncryptionHandler, ProxyData};
use mediaflow_proxy_light::auth::middleware::AuthMiddleware;

const PASSWORD: &str = "secret";
const DEST: &str = "https://cdn.example.com/stream.mkv";

/// Token minted by AIO Reborn's TypeScript code (`sealToken`, fixed nonce
/// 00 01 … 0b) for:
///   password    = "aio-reborn-contract-test"
///   destination = "https://cdn.example.com/Film.2020.1080p.mkv"
///   exp         = 4102444800 (2100-01-01)
///   endpoint    = "/proxy/stream"
/// If this test fails, the two sides no longer agree on the token format.
const AIO_REBORN_TOKEN: &str = "AQABAgMEBQYHCAkKCxp1iGpXm3yQLuTHgJ-BWoOceBGFvRdJuSGG5l-bBGfmOmgSrZTjJ2QCvGFRtD5vLOgJzwiDpaOiACdZfhQrLBghvkrwClpBok2q9qN9nrYecQgUY_KDK2ZsEhHxIyQAICyIAopRdxHSzTGceSGLaPHS4zUDoYJlUOE";

fn seal(password: &str, data: ProxyData) -> String {
    EncryptionHandler::new(password.as_bytes())
        .unwrap()
        .encrypt(&data)
        .unwrap()
}

/// A token as AIO Reborn mints it: destination, expiry, endpoint.
fn stream_token() -> String {
    seal(
        PASSWORD,
        ProxyData {
            destination: DEST.into(),
            exp: Some(unix_now() + 24 * 3600),
            endpoint: Some("/proxy/stream".into()),
        },
    )
}

// ── Token format ────────────────────────────────────────────────────────────

#[actix_web::test]
async fn opens_a_token_minted_by_aio_reborn() {
    let data = EncryptionHandler::new(b"aio-reborn-contract-test")
        .unwrap()
        .authorize(AIO_REBORN_TOKEN, "/proxy/stream/Film.2020.1080p.mkv")
        .expect("AIO Reborn's token must open");
    assert_eq!(
        data.destination,
        "https://cdn.example.com/Film.2020.1080p.mkv"
    );
    assert_eq!(data.exp, Some(4_102_444_800));
    assert_eq!(data.endpoint.as_deref(), Some("/proxy/stream"));
}

/// The server's lifetime cap applies to client-minted tokens too: this one
/// expires in 2100, far beyond 48 hours.
#[actix_web::test]
async fn caps_the_lifetime_of_client_minted_tokens() {
    let capped = EncryptionHandler::new(b"aio-reborn-contract-test")
        .unwrap()
        .with_max_lifetime(172_800);
    assert!(capped.authorize(AIO_REBORN_TOKEN, "/proxy/stream").is_err());
}

#[actix_web::test]
async fn opens_only_with_the_same_password() {
    assert!(EncryptionHandler::new(b"another-password")
        .unwrap()
        .decrypt(AIO_REBORN_TOKEN)
        .is_err());
}

// ── Middleware, over HTTP ───────────────────────────────────────────────────
//
// Auth rejections propagate as an actix-web `Error`, which the real HTTP
// dispatcher turns into a 401 via `AppError`'s `ResponseError` impl; the
// helpers below render them the same way.

/// Status, all response headers (sorted) and body.
type Outcome = (u16, Vec<(String, String)>, String);

/// Echoes what the handler sees: path and query string.
async fn echo(req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().body(format!("{}?{}", req.path(), req.query_string()))
}

/// Runs `uri` through the middleware (password [`PASSWORD`], 48 h lifetime
/// cap) and returns what the client would receive.
async fn respond(uri: &str) -> Outcome {
    let app = test::init_service(
        App::new()
            .wrap(AuthMiddleware::new(PASSWORD.into(), 172_800))
            .default_service(web::to(echo)),
    )
    .await;
    let req = test::TestRequest::get().uri(uri).to_request();
    let resp = match test::try_call_service(&app, req).await {
        Ok(resp) => resp.into_parts().1.map_into_boxed_body(),
        Err(err) => err.error_response(),
    };
    let status = resp.status().as_u16();
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    headers.sort();
    let body = actix_web::body::to_bytes(resp.into_body())
        .await
        .unwrap_or_default();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

async fn status_and_body(uri: &str) -> (u16, String) {
    let (status, _, body) = respond(uri).await;
    (status, body)
}

const GENERIC_401: &str = r#"{"error":"Invalid or expired token"}"#;
const MISSING_AUTH_401: &str = r#"{"error":"Invalid or missing authentication"}"#;

#[actix_web::test]
async fn path_token_reaches_the_endpoint_with_its_filename() {
    let token = stream_token();
    assert_eq!(
        status_and_body(&format!("/_token_{token}/proxy/stream")).await,
        (200, "/proxy/stream?".to_string())
    );
    assert_eq!(
        status_and_body(&format!("/_token_{token}/proxy/stream/Film%20(2020).mkv")).await,
        (200, "/proxy/stream/Film%20(2020).mkv?".to_string())
    );
}

/// Nothing appended to a token URL reaches the handler: the token carries
/// everything a stream needs.
#[actix_web::test]
async fn query_string_on_a_token_url_is_dropped() {
    let token = stream_token();
    assert_eq!(
        status_and_body(&format!(
            "/_token_{token}/proxy/stream?d=http://192.168.1.1/&h_referer=x&api_password=secret"
        ))
        .await,
        (200, "/proxy/stream?".to_string())
    );
}

/// Streams are only reachable through a path token: no `?token=`, no
/// `?api_password=`.
#[actix_web::test]
async fn streams_need_a_path_token() {
    let token = stream_token();
    for uri in [
        format!("/proxy/stream?token={token}"),
        format!("/proxy/stream/movie.mkv?token={token}"),
        format!("/proxy/stream?api_password={PASSWORD}&d=https://cdn.example.com/x.mkv"),
        "/proxy/stream?d=https://cdn.example.com/x.mkv".to_string(),
        "/proxy/stream".to_string(),
    ] {
        assert_eq!(
            status_and_body(&uri).await,
            (401, MISSING_AUTH_401.to_string()),
            "{uri}"
        );
    }
}

#[actix_web::test]
async fn public_ip_takes_the_api_password() {
    assert_eq!(
        status_and_body(&format!("/proxy/ip?api_password={PASSWORD}")).await,
        (200, "/proxy/ip?api_password=secret".to_string())
    );
    for uri in [
        "/proxy/ip",
        "/proxy/ip?api_password=wrong",
        "/proxy/ip?api_password=",
    ] {
        assert_eq!(
            status_and_body(uri).await,
            (401, MISSING_AUTH_401.to_string()),
            "{uri}"
        );
    }
}

#[actix_web::test]
async fn removed_routes_are_not_open() {
    for uri in [
        "/generate_urls",
        "/generate_url",
        "/proxy/forward",
        "/base64/encode",
    ] {
        assert_eq!(status_and_body(uri).await.0, 401, "{uri}");
    }
}

/// Every way a token can be refused looks exactly the same to the client:
/// status, headers and body.
#[actix_web::test]
async fn every_token_rejection_is_identical_over_http() {
    let token = stream_token();
    let mut tampered = token.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    let mut raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
    raw[0] = raw[0].wrapping_add(1);
    let other_version = URL_SAFE_NO_PAD.encode(&raw);
    let with = |exp: Option<u64>, destination: &str| {
        seal(
            PASSWORD,
            ProxyData {
                destination: destination.into(),
                exp,
                endpoint: Some("/proxy/stream".into()),
            },
        )
    };
    let other_key = seal(
        "other",
        ProxyData {
            destination: DEST.into(),
            exp: Some(unix_now() + 60),
            endpoint: Some("/proxy/stream".into()),
        },
    );
    let expired = with(Some(1), DEST);
    let no_expiry = with(None, DEST);
    let too_long = with(Some(unix_now() + 10 * 24 * 3600), DEST);
    let no_destination = with(Some(unix_now() + 60), "");
    // Python-era AES-CBC token (password "test_secret").
    let legacy =
        "AAECAwQFBgcICQoLDA0OD1NDNLU6BmO_093POOmfhHoL29QQVC_7Zf3ZkxMIV0AmCCVw7DPCWWcA59PdeoN7PQ";

    let cases: Vec<(&str, String)> = vec![
        ("tampered", format!("/_token_{tampered}/proxy/stream")),
        (
            "other version",
            format!("/_token_{other_version}/proxy/stream"),
        ),
        ("other key", format!("/_token_{other_key}/proxy/stream")),
        ("legacy cbc", format!("/_token_{legacy}/proxy/stream")),
        ("garbage", "/_token_AAAA/proxy/stream".into()),
        ("not base64", "/_token_%21%21/proxy/stream".into()),
        ("empty token", "/_token_/proxy/stream".into()),
        ("expired", format!("/_token_{expired}/proxy/stream")),
        ("no expiry", format!("/_token_{no_expiry}/proxy/stream")),
        ("lives too long", format!("/_token_{too_long}/proxy/stream")),
        (
            "no destination",
            format!("/_token_{no_destination}/proxy/stream"),
        ),
        ("other endpoint", format!("/_token_{token}/proxy/ip")),
        ("dashboard", format!("/_token_{token}/dashboard/stats")),
        ("root", format!("/_token_{token}/")),
        ("no endpoint", format!("/_token_{token}")),
        ("lookalike", format!("/_token_{token}/proxy/streamx")),
        ("encoded", format!("/_token_{token}/proxy/%73tream")),
        ("dot segment", format!("/_token_{token}/proxy/stream/../ip")),
        ("double slash", format!("/_token_{token}//proxy/stream")),
    ];

    let reference = respond(&cases[0].1).await;
    assert_eq!(reference.0, 401);
    assert_eq!(reference.2, GENERIC_401);
    for (case, uri) in &cases {
        assert_eq!(&respond(uri).await, &reference, "{case}");
    }
}

/// After the middleware rewrites `/_token_{t}/proxy/stream` to
/// `/proxy/stream`, the router must still reach the `/proxy` scope, and the
/// token's destination must flow through to the handler.
#[actix_web::test]
async fn token_path_routes_to_the_proxy_stream_scope() {
    use actix_web::web::ReqData;

    async fn stub(proxy_data: ReqData<ProxyData>) -> HttpResponse {
        HttpResponse::Ok().body(proxy_data.destination.clone())
    }

    let app = test::init_service(
        App::new()
            .wrap(AuthMiddleware::new(PASSWORD.into(), 172_800))
            .service(
                web::scope("/proxy")
                    .route("/stream", web::get().to(stub))
                    .route("/stream/{filename:.*}", web::get().to(stub)),
            ),
    )
    .await;
    for suffix in ["", "/movie.mkv"] {
        let req = test::TestRequest::get()
            .uri(&format!("/_token_{}/proxy/stream{suffix}", stream_token()))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "{suffix}");
        assert_eq!(test::read_body(resp).await, DEST, "{suffix}");
    }
}
