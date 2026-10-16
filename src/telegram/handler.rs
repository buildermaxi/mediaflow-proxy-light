//! Telegram MTProto proxy route handlers.
//!
//! Routes (registered under `/proxy/telegram`):
//! - `GET  /proxy/telegram/stream`             — stream Telegram media by file_id
//! - `HEAD /proxy/telegram/stream`             — same, no body
//! - `GET  /proxy/telegram/stream/{filename}`  — same, cosmetic filename variant
//! - `HEAD /proxy/telegram/stream/{filename}`  — same, no body
//! - `GET  /proxy/telegram/info`               — get metadata
//! - `GET  /proxy/telegram/status`             — session status

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use actix_web::{
    body::SizedStream,
    web::{self, Bytes},
    HttpRequest, HttpResponse,
};
use futures::stream;

use crate::{
    config::Config,
    error::{AppError, AppResult},
    metrics::AppMetrics,
    telegram::{
        media_ref::{decode_file_id, parse_telegram_url},
        session::get_manager,
    },
};

// ---------------------------------------------------------------------------
// Stream handler (GET + HEAD)
// ---------------------------------------------------------------------------

/// Stream or probe a Telegram document.
///
/// Supports multiple resolution modes (priority order):
/// 1. `d`/`url` — t.me URL (parsed to chat_id + message_id or file_id)
/// 2. `chat_id` + `message_id` — fetches message fresh from Telegram API
/// 3. `chat_id` + `document_id` — scans chat history
/// 4. `chat_id` + `file_id` — decodes file_id to doc_id, then scans history
/// 5. `file_id` + `file_size` — standalone (file_size required in this mode only)
pub async fn telegram_stream_handler(
    req: HttpRequest,
    config: web::Data<Arc<Config>>,
    metrics: web::Data<Arc<AppMetrics>>,
) -> AppResult<HttpResponse> {
    metrics.inc_request();
    metrics.telegram_requests.fetch_add(1, Ordering::Relaxed);
    let is_head = req.method() == actix_web::http::Method::HEAD;

    let query: HashMap<String, String> =
        web::Query::<HashMap<String, String>>::from_query(req.query_string())
            .map(|q| q.into_inner())
            .unwrap_or_default();

    // --- Parse all query params as optional ------------------------------
    let url_param = query.get("d").or_else(|| query.get("url")).cloned();
    let mut chat_id_opt = query.get("chat_id").cloned();
    let mut message_id_opt: Option<i32> = query.get("message_id").and_then(|v| v.parse().ok());
    let document_id_opt: Option<i64> = query.get("document_id").and_then(|v| v.parse().ok());
    let mut file_id_opt = query.get("file_id").cloned();
    let file_size_opt: Option<u64> = query.get("file_size").and_then(|v| v.parse().ok());

    // --- Step 1: Parse t.me URL if provided ------------------------------
    if let Some(ref url) = url_param {
        match parse_telegram_url(url) {
            Some(crate::telegram::media_ref::TelegramMediaRef::Message { chat, message_id }) => {
                use crate::telegram::media_ref::TelegramChat;
                let effective_chat = match chat {
                    TelegramChat::Id(id) if id > 0 => format!("-100{}", id),
                    TelegramChat::Id(id) => id.to_string(),
                    TelegramChat::Username(u) => u,
                };
                // URL values take priority over query params
                if chat_id_opt.is_none() {
                    chat_id_opt = Some(effective_chat);
                }
                if message_id_opt.is_none() {
                    message_id_opt = Some(message_id as i32);
                }
            }
            Some(crate::telegram::media_ref::TelegramMediaRef::FileId(fid)) => {
                if file_id_opt.is_none() {
                    file_id_opt = Some(fid);
                }
            }
            None => {
                return Err(AppError::BadRequest(format!(
                    "Cannot parse Telegram URL: {}",
                    url
                )));
            }
        }
    }

    // --- Check Telegram config -------------------------------------------
    let tg_cfg = &config.telegram;
    if tg_cfg.api_id == 0 || tg_cfg.api_hash.is_empty() || tg_cfg.session_string.is_empty() {
        return Err(AppError::Telegram(
            "Telegram not configured. Set APP__TELEGRAM__API_ID, \
             APP__TELEGRAM__API_HASH and APP__TELEGRAM__SESSION_STRING."
                .into(),
        ));
    }

    // --- Initialise (or reuse) the Telegram client -----------------------
    #[cfg(not(feature = "telegram"))]
    return Err(AppError::Telegram(
        "Telegram feature not compiled in.".into(),
    ));

    #[cfg(feature = "telegram")]
    {
        use crate::proxy::stream::ResponseStream;
        use crate::telegram::session::{
            get_fresh_document_info, get_location_from_message_id, get_or_init_client,
            stream_document_range, FreshFileLocation,
        };
        use grammers_tl_types as tl;

        let client = get_or_init_client(tg_cfg)
            .await
            .map_err(|e| AppError::Telegram(format!("Telegram connect failed: {}", e)))?;

        // --- Step 2: Resolve to a file location --------------------------
        enum Resolved {
            Fresh(FreshFileLocation),
            /// file_id-only mode: use decoded fields + caller-supplied file_size
            FileIdDirect {
                doc_id: i64,
                access_hash: i64,
                file_reference: Vec<u8>,
                dc_id: i32,
                file_size: u64,
            },
        }

        let resolved: Resolved = if let (Some(chat_id), Some(msg_id)) =
            (&chat_id_opt, message_id_opt)
        {
            // Mode 2: chat_id + message_id → fetch fresh from Telegram
            match get_location_from_message_id(client.clone(), chat_id, msg_id).await {
                Some(loc) => Resolved::Fresh(loc),
                None => {
                    return Err(AppError::NotFound(format!(
                        "No document found in message_id={} chat={}",
                        msg_id, chat_id
                    )));
                }
            }
        } else if let (Some(chat_id), Some(doc_id)) = (&chat_id_opt, document_id_opt) {
            // Mode 3: chat_id + document_id → scan history
            match get_fresh_document_info(client.clone(), chat_id, doc_id, None, 200).await {
                Some(loc) => Resolved::Fresh(loc),
                None => {
                    return Err(AppError::NotFound(format!(
                        "document_id={} not found in chat={}",
                        doc_id, chat_id
                    )));
                }
            }
        } else if let (Some(chat_id), Some(ref fid)) = (&chat_id_opt, &file_id_opt) {
            // Mode 4: chat_id + file_id → decode file_id to get doc_id, scan history
            let decoded = decode_file_id(fid)
                .ok_or_else(|| AppError::BadRequest("Cannot decode file_id".into()))?;
            match get_fresh_document_info(client.clone(), chat_id, decoded.id, None, 200).await {
                Some(loc) => Resolved::Fresh(loc),
                None => {
                    // Fallback: use file_id embedded values but file_size is required
                    let fs = file_size_opt.ok_or_else(|| {
                        AppError::BadRequest(
                            "document not found in chat history and file_size not provided \
                                 for file_id fallback"
                                .into(),
                        )
                    })?;
                    if fs == 0 {
                        return Err(AppError::BadRequest("file_size must be > 0".into()));
                    }
                    tracing::warn!(
                        "Could not find document_id={} in chat history; \
                             falling back to file_id embedded values",
                        decoded.id
                    );
                    Resolved::FileIdDirect {
                        doc_id: decoded.id,
                        access_hash: decoded.access_hash,
                        file_reference: decoded.file_reference,
                        dc_id: decoded.dc_id,
                        file_size: fs,
                    }
                }
            }
        } else if let Some(ref fid) = file_id_opt {
            // Mode 5: file_id + file_size (standalone)
            let fs = file_size_opt.ok_or_else(|| {
                AppError::BadRequest(
                    "file_size is required when using file_id without chat_id".into(),
                )
            })?;
            if fs == 0 {
                return Err(AppError::BadRequest("file_size must be > 0".into()));
            }
            let decoded = decode_file_id(fid)
                .ok_or_else(|| AppError::BadRequest("Cannot decode file_id".into()))?;
            Resolved::FileIdDirect {
                doc_id: decoded.id,
                access_hash: decoded.access_hash,
                file_reference: decoded.file_reference,
                dc_id: decoded.dc_id,
                file_size: fs,
            }
        } else {
            return Err(AppError::BadRequest(
                "No resolvable parameters provided. Supported modes: \
                     (1) d/url=<t.me URL>, \
                     (2) chat_id + message_id, \
                     (3) chat_id + document_id, \
                     (4) chat_id + file_id, \
                     (5) file_id + file_size"
                    .into(),
            ));
        };

        // --- Step 3: Extract location fields and file metadata -----------
        let (doc_id, access_hash, file_reference, dc_id, file_size, mime_opt, fname_opt) =
            match resolved {
                Resolved::Fresh(loc) => (
                    loc.document_id,
                    loc.access_hash,
                    loc.file_reference,
                    loc.dc_id,
                    loc.file_size,
                    Some(loc.mime_type),
                    loc.file_name,
                ),
                Resolved::FileIdDirect {
                    doc_id,
                    access_hash,
                    file_reference,
                    dc_id,
                    file_size,
                } => (
                    doc_id,
                    access_hash,
                    file_reference,
                    dc_id,
                    file_size,
                    None,
                    None,
                ),
            };

        // --- Build file location -----------------------------------------
        let location = tl::enums::InputFileLocation::InputDocumentFileLocation(
            tl::types::InputDocumentFileLocation {
                id: doc_id,
                access_hash,
                file_reference,
                thumb_size: String::new(),
            },
        );

        // --- Determine MIME type -----------------------------------------
        // Priority: from document attributes → from path/filename param → octet-stream
        let path_filename = req.match_info().get("filename").unwrap_or("stream.mkv");
        let effective_filename = fname_opt.as_deref().unwrap_or(path_filename);
        let mime = mime_opt.unwrap_or_else(|| {
            mime_guess::from_path(effective_filename)
                .first_or_octet_stream()
                .to_string()
        });

        // --- Parse Range header ------------------------------------------
        let range_header = req
            .headers()
            .get("range")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let (start, end) = parse_range(range_header.as_deref(), file_size);

        tracing::debug!(
            "tg handler: file_size={} range_header={:?} parsed start={} end={} content_length={}",
            file_size,
            range_header,
            start,
            end,
            end - start + 1
        );

        // --- Build response headers --------------------------------------
        let content_length = end - start + 1;
        let is_range_request = range_header.is_some();

        let status_code = if is_range_request { 206u16 } else { 200u16 };

        let mut response = HttpResponse::build(
            actix_web::http::StatusCode::from_u16(status_code)
                .unwrap_or(actix_web::http::StatusCode::OK),
        );
        response.insert_header(("content-type", mime.as_str()));
        response.insert_header(("accept-ranges", "bytes"));
        response.insert_header(("content-length", content_length.to_string()));
        if is_range_request {
            response.insert_header((
                "content-range",
                format!("bytes {}-{}/{}", start, end, file_size),
            ));
        }

        // HEAD: return headers only, no body
        if is_head {
            let empty = Box::pin(stream::empty::<Result<Bytes, std::io::Error>>());
            return Ok(response
                .no_chunking(content_length)
                .body(SizedStream::new(content_length, empty)));
        }

        // GET: stream body
        let byte_stream =
            stream_document_range(client, tg_cfg.clone(), location, dc_id, start, end).await;
        let response_stream = ResponseStream::new(byte_stream);

        Ok(response
            .no_chunking(content_length)
            .body(SizedStream::new(content_length, response_stream)))
    }
}

// ---------------------------------------------------------------------------
// Info handler
// ---------------------------------------------------------------------------

pub async fn telegram_info_handler(
    req: HttpRequest,
    _config: web::Data<Arc<Config>>,
) -> AppResult<HttpResponse> {
    let query: HashMap<String, String> =
        web::Query::<HashMap<String, String>>::from_query(req.query_string())
            .map(|q| q.into_inner())
            .unwrap_or_default();

    let url = query
        .get("url")
        .or_else(|| query.get("d"))
        .cloned()
        .ok_or_else(|| AppError::BadRequest("Missing url/d param".into()))?;

    let media_ref = parse_telegram_url(&url)
        .ok_or_else(|| AppError::BadRequest(format!("Cannot parse Telegram URL: {url}")))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "url": url,
        "parsed": format!("{media_ref:?}"),
    })))
}

// ---------------------------------------------------------------------------
// Status handler
// ---------------------------------------------------------------------------

pub async fn telegram_status_handler(config: web::Data<Arc<Config>>) -> AppResult<HttpResponse> {
    // The web UI's status widget (static/url_generator.html) switches on a
    // string `status` field: "connected" / "ready" / "disabled" /
    // "not_connected".  Emit both the legacy boolean + the string shape so
    // older callers still work.
    let status = connection_status(&config.telegram).await;
    let configured =
        crate::telegram::session::TelegramSessionManager::is_configured(&config.telegram);
    let manager = get_manager();
    let mgr = manager.read().await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": status,
        "connected": mgr.is_authorized(),
        "configured": configured,
        "session_file": mgr.session_file,
    })))
}

/// `"connected"`, `"not_connected"` or `"disabled"` (no credentials configured).
pub async fn connection_status(config: &crate::config::TelegramConfig) -> &'static str {
    if !crate::telegram::session::TelegramSessionManager::is_configured(config) {
        "disabled"
    } else if get_manager().read().await.is_authorized() {
        "connected"
    } else {
        "not_connected"
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse an HTTP `Range: bytes=start-end` header.
///
/// Returns `(start, end)` (both inclusive) clamped to `[0, file_size-1]`.
fn parse_range(header: Option<&str>, file_size: u64) -> (u64, u64) {
    let header = match header {
        Some(h) => h,
        None => return (0, file_size.saturating_sub(1)),
    };

    // Expected format: "bytes=start-end" or "bytes=-suffix_len"
    let bytes_part = header.strip_prefix("bytes=").unwrap_or(header);
    let (start_str, end_str) = match bytes_part.split_once('-') {
        Some(pair) => pair,
        None => return (0, file_size.saturating_sub(1)),
    };

    if start_str.is_empty() {
        // Suffix-range: "bytes=-N" means last N bytes.
        // end_str is the count (N), NOT an end offset.
        let suffix_len = end_str.parse::<u64>().unwrap_or(0).min(file_size);
        let start = file_size.saturating_sub(suffix_len);
        let end = file_size.saturating_sub(1);
        return (start, end);
    }

    let start = start_str.parse::<u64>().unwrap_or(0);

    let end = if end_str.is_empty() {
        file_size.saturating_sub(1)
    } else {
        end_str
            .parse::<u64>()
            .unwrap_or(file_size.saturating_sub(1))
            .min(file_size.saturating_sub(1))
    };

    if start > end {
        return (0, file_size.saturating_sub(1));
    }

    (start, end)
}
