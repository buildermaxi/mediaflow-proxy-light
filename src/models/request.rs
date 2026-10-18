pub const SUPPORTED_RESPONSE_HEADERS: &[&str] = &[
    "accept-ranges",
    "content-type",
    "content-length",
    "content-range",
    "connection",
    "transfer-encoding",
    "last-modified",
    "etag",
    "cache-control",
    "expires",
];

pub const SUPPORTED_REQUEST_HEADERS: &[&str] = &["range", "if-range"];
