//! Encrypted, authenticated proxy tokens (the `/_token_…/` path prefix).
//!
//! A token is `base64url-no-pad(version[1] || nonce[12] || AES-256-GCM(json))`,
//! where `json` is the serialised [`ProxyData`]. The AES key is derived from
//! the API password with HKDF-SHA256 (no salt, `info` = [`KEY_INFO`]), and the
//! version-tagged [`TOKEN_AAD`] is authenticated alongside.
//!
//! Tokens are minted by the client that holds the API password (AIO Reborn
//! does it in its Cloudflare Worker); the server only opens them. This format
//! is therefore a contract: changing it means bumping [`TOKEN_VERSION`] and
//! updating the client in step.
//!
//! GCM authenticates the ciphertext: a token that was not minted with the
//! API password, or that was modified in any way, fails before its contents
//! are looked at. Every rejection — malformed, forged, tampered, expired,
//! living longer than the server allows, or bound to another endpoint —
//! returns the same [`INVALID_TOKEN`] error, so a client can't tell the
//! failure modes apart. The precise reason is only logged at `debug` level.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AppError;

/// The only error message a client ever sees for a rejected token.
pub const INVALID_TOKEN: &str = "Invalid or expired token";

/// Leading byte of every token, so the format can change without ambiguity.
const TOKEN_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// HKDF `info`: ties the derived key to this one purpose.
const KEY_INFO: &[u8] = b"mediaflow-proxy-light/token-key/v1";
/// Associated data authenticated alongside every token, followed by the
/// version byte (see [`token_aad`]).
const TOKEN_AAD: &[u8] = b"mediaflow-proxy-light/token";

/// What a token carries. Unknown fields are ignored, so tokens minted by an
/// older client with extra fields still open.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProxyData {
    /// Upstream URL the stream is read from.
    pub destination: String,
    /// Unix timestamp (seconds) after which the token is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Endpoint the token was minted for (e.g. `/proxy/stream`). A token is
    /// only accepted on that path or below it (`/proxy/stream/<filename>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Opens (and, for tests and tools, seals) proxy tokens with a key derived
/// from the API password.
#[derive(Clone)]
pub struct EncryptionHandler {
    cipher: Aes256Gcm,
    /// Longest remaining lifetime, in seconds, a token may claim; `0` means
    /// no limit. With a limit, a token must carry an expiry.
    max_lifetime: u64,
}

impl EncryptionHandler {
    pub fn new(api_password: &[u8]) -> Result<Self, AppError> {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, api_password)
            .expand(KEY_INFO, &mut key)
            .map_err(|_| AppError::Internal("Failed to derive the token key".to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| AppError::Internal("Failed to initialise the token cipher".to_string()))?;
        Ok(Self {
            cipher,
            max_lifetime: 0,
        })
    }

    /// Refuse tokens without an expiry, or whose expiry is more than
    /// `seconds` away (`0` lifts the limit). Bounds how long a leaked URL
    /// stays usable, whatever lifetime the client asked for.
    pub fn with_max_lifetime(mut self, seconds: u64) -> Self {
        self.max_lifetime = seconds;
        self
    }

    pub fn encrypt(&self, data: &ProxyData) -> Result<String, AppError> {
        let plaintext = serde_json::to_vec(data)
            .map_err(|e| AppError::Internal(format!("Failed to serialize proxy data: {}", e)))?;

        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);

        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &token_aad(TOKEN_VERSION),
                },
            )
            .map_err(|_| AppError::Internal("Failed to encrypt proxy data".to_string()))?;

        let mut token = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        token.push(TOKEN_VERSION);
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(token))
    }

    /// Opens `token` and checks its expiry and lifetime, without checking
    /// which endpoint it is used on. Requests go through [`Self::authorize`].
    pub fn decrypt(&self, token: &str) -> Result<ProxyData, AppError> {
        self.open(token).map_err(reject)
    }

    /// Opens `token` for a request to `path` (the path after the `/_token_…`
    /// prefix has been removed). On top of [`Self::decrypt`], the token must
    /// have been minted for the endpoint `path` is on.
    pub fn authorize(&self, token: &str, path: &str) -> Result<ProxyData, AppError> {
        self.open(token)
            .and_then(|data| {
                if endpoint_allows(data.endpoint.as_deref(), path) {
                    Ok(data)
                } else {
                    Err("token not valid for this endpoint")
                }
            })
            .map_err(reject)
    }

    fn open(&self, token: &str) -> Result<ProxyData, &'static str> {
        let raw = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| "token is not base64url")?;
        if raw.len() < 1 + NONCE_LEN + TAG_LEN {
            return Err("token too short");
        }
        let (version, rest) = raw.split_at(1);
        if version[0] != TOKEN_VERSION {
            return Err("unknown token version");
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);

        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &token_aad(version[0]),
                },
            )
            .map_err(|_| "token failed authentication")?;

        let data: ProxyData =
            serde_json::from_slice(&plaintext).map_err(|_| "token payload is not valid")?;

        if data.destination.is_empty() {
            return Err("token has no destination");
        }
        let now = unix_now();
        if data.exp.is_some_and(|exp| exp < now) {
            return Err("token has expired");
        }
        if self.max_lifetime > 0 {
            match data.exp {
                None => return Err("token has no expiry"),
                Some(exp) if exp > now.saturating_add(self.max_lifetime) => {
                    return Err("token lives longer than the server allows")
                }
                Some(_) => {}
            }
        }
        Ok(data)
    }
}

/// Whether a token minted for `endpoint` may be used on `path`: the path must
/// be the endpoint itself or sit below it (`/proxy/stream/<filename>`), and
/// may not contain `.` or `..` segments, even percent-encoded.
fn endpoint_allows(endpoint: Option<&str>, path: &str) -> bool {
    let Some(endpoint) = endpoint.map(|e| e.trim_end_matches('/')) else {
        return false;
    };
    if endpoint.is_empty() || !endpoint.starts_with('/') {
        return false;
    }
    if has_dot_segment(path) || has_dot_segment(endpoint) {
        return false;
    }
    path == endpoint
        || path
            .strip_prefix(endpoint)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(|segment| {
        let decoded = urlencoding::decode(segment).unwrap_or_else(|_| segment.into());
        decoded == "." || decoded == ".."
    })
}

/// Associated data for a token of `version`.
fn token_aad(version: u8) -> Vec<u8> {
    let mut aad = TOKEN_AAD.to_vec();
    aad.push(version);
    aad
}

fn reject(reason: &'static str) -> AppError {
    tracing::debug!("rejected proxy token: {reason}");
    AppError::Auth(INVALID_TOKEN.to_string())
}

/// Current Unix time in seconds (0 if the clock is before 1970).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST: &str = "https://example.com/stream.mkv";

    fn handler() -> EncryptionHandler {
        EncryptionHandler::new(b"test_password").unwrap()
    }

    fn stream_data() -> ProxyData {
        ProxyData {
            destination: DEST.to_string(),
            endpoint: Some("/proxy/stream".to_string()),
            ..Default::default()
        }
    }

    fn error_message(result: Result<ProxyData, AppError>) -> String {
        match result {
            Err(AppError::Auth(msg)) => msg,
            Err(other) => panic!("expected an auth error, got {other:?}"),
            Ok(data) => panic!("expected a rejection, got {data:?}"),
        }
    }

    #[test]
    fn round_trip() {
        let token = handler().encrypt(&stream_data()).unwrap();
        let data = handler().decrypt(&token).unwrap();
        assert_eq!(data.destination, DEST);
        assert_eq!(data.endpoint.as_deref(), Some("/proxy/stream"));
    }

    #[test]
    fn each_token_uses_a_fresh_nonce() {
        let h = handler();
        assert_ne!(
            h.encrypt(&stream_data()).unwrap(),
            h.encrypt(&stream_data()).unwrap()
        );
    }

    #[test]
    fn token_from_another_password_is_rejected() {
        let token = EncryptionHandler::new(b"other_password")
            .unwrap()
            .encrypt(&stream_data())
            .unwrap();
        assert_eq!(error_message(handler().decrypt(&token)), INVALID_TOKEN);
    }

    /// Flipping any single bit anywhere in the token must be detected.
    #[test]
    fn every_modification_is_rejected() {
        let h = handler();
        let raw = URL_SAFE_NO_PAD
            .decode(h.encrypt(&stream_data()).unwrap())
            .unwrap();
        for i in 0..raw.len() {
            for bit in 0..8 {
                let mut tampered = raw.clone();
                tampered[i] ^= 1 << bit;
                let token = URL_SAFE_NO_PAD.encode(&tampered);
                assert_eq!(
                    error_message(h.decrypt(&token)),
                    INVALID_TOKEN,
                    "byte {i} bit {bit}"
                );
            }
        }
    }

    /// No failure mode may be distinguishable from another by its response.
    #[test]
    fn all_failures_share_one_error() {
        let h = handler();
        let seal = |data: ProxyData| h.encrypt(&data).unwrap();
        let valid = seal(stream_data());
        let raw = URL_SAFE_NO_PAD.decode(&valid).unwrap();
        let truncated = URL_SAFE_NO_PAD.encode(&raw[..raw.len() - 1]);
        let mut wrong_version = raw.clone();
        wrong_version[0] = TOKEN_VERSION + 1;
        let wrong_version = URL_SAFE_NO_PAD.encode(&wrong_version);

        let failures: Vec<(&str, Result<ProxyData, AppError>)> = vec![
            ("not base64", h.decrypt("not base64!")),
            ("empty", h.decrypt("")),
            (
                "too short",
                h.decrypt(&URL_SAFE_NO_PAD.encode([TOKEN_VERSION; 8])),
            ),
            ("truncated", h.decrypt(&truncated)),
            ("wrong version", h.decrypt(&wrong_version)),
            (
                "expired",
                h.decrypt(&seal(ProxyData {
                    exp: Some(1),
                    ..stream_data()
                })),
            ),
            (
                "no destination",
                h.decrypt(&seal(ProxyData {
                    destination: String::new(),
                    ..stream_data()
                })),
            ),
            (
                "no expiry under a lifetime limit",
                h.clone().with_max_lifetime(3600).decrypt(&valid),
            ),
            (
                "lives too long",
                h.clone().with_max_lifetime(3600).decrypt(&seal(ProxyData {
                    exp: Some(unix_now() + 7200),
                    ..stream_data()
                })),
            ),
            ("wrong endpoint", h.authorize(&valid, "/proxy/ip")),
        ];
        for (case, result) in failures {
            assert_eq!(error_message(result), INVALID_TOKEN, "{case}");
        }
    }

    /// A token in the old AES-CBC format (generated by the Python proxy with
    /// the password "test_secret") is no longer accepted.
    #[test]
    fn legacy_cbc_token_is_rejected() {
        let legacy = "AAECAwQFBgcICQoLDA0OD1NDNLU6BmO_093POOmfhHoL29QQVC_7Zf3ZkxMIV0AmCCVw7DPCWWcA59PdeoN7PQ";
        let h = EncryptionHandler::new(b"test_secret").unwrap();
        assert_eq!(error_message(h.decrypt(legacy)), INVALID_TOKEN);
    }

    #[test]
    fn future_expiry_within_the_lifetime_limit_is_accepted() {
        let h = handler().with_max_lifetime(3600);
        let token = h
            .encrypt(&ProxyData {
                exp: Some(unix_now() + 1800),
                ..stream_data()
            })
            .unwrap();
        assert!(h.decrypt(&token).is_ok());
        // Without a limit, a token may also carry no expiry at all.
        assert!(handler()
            .decrypt(&handler().encrypt(&stream_data()).unwrap())
            .is_ok());
    }

    /// Fields a previous version of the payload carried (headers, client IP…)
    /// are ignored rather than failing the token.
    #[test]
    fn unknown_payload_fields_are_ignored() {
        let data: ProxyData = serde_json::from_str(
            r#"{"destination":"https://a/b","ip":"1.2.3.4","request_headers":{"x":"y"},"endpoint":"/proxy/stream"}"#,
        )
        .unwrap();
        assert_eq!(data.destination, "https://a/b");
        assert_eq!(data.endpoint.as_deref(), Some("/proxy/stream"));
    }

    #[test]
    fn endpoint_binding() {
        let h = handler();
        let token = h.encrypt(&stream_data()).unwrap();
        for ok in ["/proxy/stream", "/proxy/stream/", "/proxy/stream/movie.mkv"] {
            assert!(h.authorize(&token, ok).is_ok(), "{ok}");
        }
        for denied in [
            "/proxy/ip",
            "/proxy/streamer",
            "/proxy",
            "/",
            "/dashboard/stats",
            "",
            "//proxy/stream",
            "/proxy/%73tream",
            "/proxy/stream/../ip",
            "/proxy/stream/%2e%2e/ip",
            "/proxy/stream/%2E./ip",
            "/proxy/stream/./movie.mkv",
        ] {
            assert!(h.authorize(&token, denied).is_err(), "{denied}");
        }
    }

    #[test]
    fn token_without_endpoint_authorizes_nothing() {
        let h = handler();
        let token = h
            .encrypt(&ProxyData {
                endpoint: None,
                ..stream_data()
            })
            .unwrap();
        assert!(h.decrypt(&token).is_ok());
        assert!(h.authorize(&token, "/proxy/stream").is_err());
    }

    #[test]
    fn endpoint_allows_rejects_degenerate_endpoints() {
        for endpoint in ["", "/", "proxy/stream"] {
            assert!(
                !endpoint_allows(Some(endpoint), "/proxy/stream"),
                "{endpoint}"
            );
        }
        assert!(endpoint_allows(
            Some("/proxy/stream/"),
            "/proxy/stream/a.mkv"
        ));
    }
}
