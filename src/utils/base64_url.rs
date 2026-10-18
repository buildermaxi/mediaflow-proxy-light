/// Utilities for detecting and handling base64-encoded URLs.
/// Port of Python `mediaflow_proxy/utils/base64_utils.py`.
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};

/// Try to decode a (possibly URL-safe) base64 string as a URL.
///
/// Returns `Some(url)` if the decoded bytes are valid UTF-8 and parse as
/// a URL with a scheme and host; `None` otherwise.
pub fn decode_base64_url(encoded: &str) -> Option<String> {
    // Normalise URL-safe variants (- → +, _ → /)
    let normalised = encoded.replace('-', "+").replace('_', "/");

    // Add missing padding
    let padding = (4 - normalised.len() % 4) % 4;
    let padded = format!("{}{}", normalised, "=".repeat(padding));

    let bytes = general_purpose::STANDARD.decode(&padded).ok()?;
    let s = String::from_utf8(bytes).ok()?;

    // Validate: must have a scheme and a host
    let parsed = url::Url::parse(&s).ok()?;
    if parsed.scheme().is_empty() || parsed.host().is_none() {
        return None;
    }

    Some(s)
}

/// Encode a URL as base64url (no padding, URL-safe alphabet).
pub fn encode_url_to_base64(url: &str) -> String {
    // URL-safe alphabet, no padding (strip trailing '=')
    let encoded = engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD)
        .encode(url.as_bytes());
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let original = "https://example.com/path/to/stream.m3u8?foo=bar&baz=qux";
        let encoded = encode_url_to_base64(original);
        let decoded = decode_base64_url(&encoded).expect("should decode");
        assert_eq!(decoded, original);
    }
}
