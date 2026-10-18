//! Cookie session for the web dashboard.
//!
//! `POST /login` checks the submitted API password and sets an `HttpOnly`
//! cookie; every dashboard route (page and JSON feeds) then verifies that
//! cookie server-side. The cookie holds an HMAC of the API password rather
//! than the password itself, so a leaked cookie can't be used to mint proxy
//! tokens, and changing the password signs every browser out.

use actix_web::cookie::{time::Duration, Cookie, SameSite};
use actix_web::HttpRequest;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const COOKIE_NAME: &str = "mfp_dashboard";

const SESSION_MAX_AGE_DAYS: i64 = 30;
const SESSION_CONTEXT: &[u8] = b"mediaflow-proxy-light/dashboard-session/v1";

/// Session value for `api_password`: hex HMAC-SHA256 keyed by the password.
fn session_value(api_password: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(api_password.as_bytes()).expect("HMAC accepts any key size");
    mac.update(SESSION_CONTEXT);
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether `password` is the configured API password. Always false when no
/// password is configured, so the dashboard is never public. Compares
/// fixed-length digests, so timing leaks neither content nor length. (Not
/// HMACs keyed by each password: HMAC zero-pads short keys, so `pw` and
/// `pw\0` would match.)
pub fn password_matches(password: &str, api_password: &str) -> bool {
    !api_password.is_empty()
        && constant_time_eq(
            &Sha256::digest(password.as_bytes()),
            &Sha256::digest(api_password.as_bytes()),
        )
}

/// Whether the request carries a valid dashboard session cookie.
pub fn is_authenticated(req: &HttpRequest, api_password: &str) -> bool {
    if api_password.is_empty() {
        return false;
    }
    req.cookie(COOKIE_NAME).is_some_and(|c| {
        constant_time_eq(c.value().as_bytes(), session_value(api_password).as_bytes())
    })
}

/// `Secure` only over HTTPS (directly or via `X-Forwarded-Proto`), so the
/// dashboard still works on a plain-HTTP LAN address.
fn is_https(req: &HttpRequest) -> bool {
    req.connection_info().scheme() == "https"
}

pub fn login_cookie(req: &HttpRequest, api_password: &str) -> Cookie<'static> {
    Cookie::build(COOKIE_NAME, session_value(api_password))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(is_https(req))
        .max_age(Duration::days(SESSION_MAX_AGE_DAYS))
        .finish()
}

pub fn logout_cookie(req: &HttpRequest) -> Cookie<'static> {
    let mut cookie = Cookie::build(COOKIE_NAME, "")
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(is_https(req))
        .finish();
    cookie.make_removal();
    cookie
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn session_cookie_round_trip() {
        let login = TestRequest::default().to_http_request();
        let cookie = login_cookie(&login, "s3cret");
        assert!(cookie.http_only().unwrap_or(false));
        assert_ne!(
            cookie.value(),
            "s3cret",
            "cookie must not carry the raw password"
        );

        let authed = TestRequest::default()
            .cookie(cookie.clone())
            .to_http_request();
        assert!(is_authenticated(&authed, "s3cret"));
        assert!(
            !is_authenticated(&authed, "other"),
            "password change signs out"
        );
        assert!(
            !is_authenticated(&authed, ""),
            "no password configured => locked"
        );

        let forged = TestRequest::default()
            .cookie(Cookie::new(COOKIE_NAME, "s3cret"))
            .to_http_request();
        assert!(!is_authenticated(&forged, "s3cret"));
        assert!(!is_authenticated(
            &TestRequest::default().to_http_request(),
            "s3cret"
        ));
    }

    #[test]
    fn password_check() {
        assert!(password_matches("s3cret", "s3cret"));
        assert!(!password_matches("nope", "s3cret"));
        assert!(!password_matches("s3cret\0", "s3cret"));
        assert!(!password_matches("s3cre", "s3cret"));
        assert!(
            !password_matches("", ""),
            "empty configured password never matches"
        );
    }
}
