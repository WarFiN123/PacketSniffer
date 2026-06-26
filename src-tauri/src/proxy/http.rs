// ─── HTTP Session & Body Utilities ───────────────────────────────────────────
// Defines HttpSession (the JSON struct sent to the UI) and helpers for body
// decompression, binary detection, and conversion from hyper types.

use serde::Serialize;
use std::io::Read;

/// A single HTTP header name-value pair.
#[derive(Debug, Clone, Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// Parsed HTTP session (request + response) — emitted to the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpSession {
    pub id: u64,
    /// IP the proxied connection arrived from. `127.0.0.1` for the host's own
    /// traffic; a LAN IP for a phone routed through the proxy. Lets the UI
    /// separate "My computer" from each connected device.
    pub client_addr: String,
    pub scheme: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub url: String,
    pub http_version: String,
    pub status: u16,
    pub status_text: String,
    pub resp_http_version: String,
    pub content_type: String,
    pub request_size: usize,
    pub response_size: usize,
    pub duration: f64,
    pub complete: bool,
    pub request_headers: Vec<HttpHeader>,
    pub response_headers: Vec<HttpHeader>,
    /// Request body as UTF-8 string (truncated to 256 KB for UI transport).
    /// Stripped from the live `proxy-session` event stream; fetched on demand
    /// via the `get_session` command when a row is inspected.
    pub request_body: Option<String>,
    /// Response body as UTF-8 string (truncated to 256 KB for UI transport).
    /// Stripped from the live event stream; fetched on demand.
    pub response_body: Option<String>,
    /// Whether a displayable request body exists (kept in the slim event so the
    /// UI can show the Body tab without transporting the body itself).
    pub has_request_body: bool,
    /// Whether a displayable response body exists.
    pub has_response_body: bool,
}

impl HttpSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new_request(
        id: u64,
        client_addr: &str,
        scheme: &str,
        method: &str,
        host: &str,
        path: &str,
        url: &str,
        version: &str,
        headers: Vec<HttpHeader>,
        body_size: usize,
        request_body: Option<Vec<u8>>,
    ) -> Self {
        let request_body = request_body.and_then(|b| body_for_ui(&b, None, None));
        let has_request_body = request_body.is_some();
        Self {
            id,
            client_addr: client_addr.to_string(),
            scheme: scheme.to_string(),
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            url: url.to_string(),
            http_version: version.to_string(),
            status: 0,
            status_text: String::new(),
            resp_http_version: String::new(),
            content_type: String::new(),
            request_size: body_size,
            response_size: 0,
            duration: 0.0,
            complete: false,
            request_headers: headers,
            response_headers: Vec::new(),
            request_body,
            response_body: None,
            has_request_body,
            has_response_body: false,
        }
    }

    pub fn finish(
        &mut self,
        status: u16,
        status_text: &str,
        resp_version: &str,
        content_type: &str,
        response_size: usize,
        duration_ms: f64,
        response_headers: Vec<HttpHeader>,
        response_body: Option<Vec<u8>>,
    ) {
        self.status = status;
        self.status_text = status_text.to_string();
        self.resp_http_version = resp_version.to_string();
        self.content_type = content_type.to_string();
        self.response_size = response_size;
        self.duration = duration_ms;
        self.complete = true;
        self.response_headers = response_headers;

        let encoding =
            find_header(&self.response_headers, "Content-Encoding").map(|s| s.to_string());
        self.response_body =
            response_body.and_then(|b| body_for_ui(&b, Some(content_type), encoding.as_deref()));
        self.has_response_body = self.response_body.is_some();
    }

    /// Clone everything except the (potentially large) body strings. Used to
    /// build the slim payload pushed over the `proxy-session` event stream;
    /// the body presence flags are preserved so the UI can still offer Body
    /// tabs and fetch the full bodies on demand.
    pub fn metadata_clone(&self) -> Self {
        Self {
            id: self.id,
            client_addr: self.client_addr.clone(),
            scheme: self.scheme.clone(),
            method: self.method.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            url: self.url.clone(),
            http_version: self.http_version.clone(),
            status: self.status,
            status_text: self.status_text.clone(),
            resp_http_version: self.resp_http_version.clone(),
            content_type: self.content_type.clone(),
            request_size: self.request_size,
            response_size: self.response_size,
            duration: self.duration,
            complete: self.complete,
            request_headers: self.request_headers.clone(),
            response_headers: self.response_headers.clone(),
            request_body: None,
            response_body: None,
            has_request_body: self.has_request_body,
            has_response_body: self.has_response_body,
        }
    }
}

// ─── Conversion helpers for hyper types ─────────────────────────────────────

/// Convert hyper HeaderMap to our Vec<HttpHeader>.
pub fn headers_from_hyper(map: &hyper::header::HeaderMap) -> Vec<HttpHeader> {
    map.iter()
        .map(|(name, value)| HttpHeader {
            name: name.to_string(),
            value: value.to_str().unwrap_or("<binary>").to_string(),
        })
        .collect()
}

/// Format an HTTP version from hyper's Version type.
pub fn version_str(v: hyper::http::Version) -> &'static str {
    match v {
        hyper::http::Version::HTTP_09 => "HTTP/0.9",
        hyper::http::Version::HTTP_10 => "HTTP/1.0",
        hyper::http::Version::HTTP_11 => "HTTP/1.1",
        hyper::http::Version::HTTP_2 => "HTTP/2",
        hyper::http::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/?",
    }
}

/// Check if a request is a WebSocket upgrade by examining headers.
pub fn is_websocket_upgrade(headers: &hyper::header::HeaderMap) -> bool {
    headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Find a header value by name (case-insensitive) in our HttpHeader vec.
pub fn find_header<'a>(headers: &'a [HttpHeader], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

// ─── Body processing ────────────────────────────────────────────────────────

/// Max body size to send to the UI (256 KB).
const MAX_BODY_UI: usize = 256 * 1024;

/// Check if a Content-Type is binary (images, video, audio, fonts, wasm, etc.)
fn is_binary_content_type(ct: &str) -> bool {
    let ct_lower = ct.to_ascii_lowercase();
    let mime = ct_lower.split(';').next().unwrap_or("").trim();

    if mime.starts_with("image/")
        || mime.starts_with("video/")
        || mime.starts_with("audio/")
        || mime.starts_with("font/")
    {
        return true;
    }

    matches!(
        mime,
        "application/octet-stream"
            | "application/pdf"
            | "application/zip"
            | "application/gzip"
            | "application/x-tar"
            | "application/x-gzip"
            | "application/x-bzip2"
            | "application/x-7z-compressed"
            | "application/x-rar-compressed"
            | "application/wasm"
            | "application/x-protobuf"
            | "application/protobuf"
            | "application/grpc"
            | "application/x-shockwave-flash"
            | "application/vnd.ms-fontobject"
            | "application/x-font-ttf"
            | "application/x-font-woff"
            | "application/font-woff"
            | "application/font-woff2"
    )
}

/// Prepare a body for the UI: decompress if needed, detect binary, truncate.
pub fn body_for_ui(
    body: &[u8],
    content_type: Option<&str>,
    content_encoding: Option<&str>,
) -> Option<String> {
    if body.is_empty() {
        return None;
    }

    let decompressed = match content_encoding {
        Some(enc) => {
            let enc_lower = enc.to_ascii_lowercase();
            if enc_lower.contains("br") {
                decompress_brotli(body)
            } else if enc_lower.contains("gzip") {
                decompress_gzip(body)
            } else if enc_lower.contains("deflate") {
                decompress_deflate(body)
            } else {
                None
            }
        }
        None => None,
    };

    let data = decompressed.as_deref().unwrap_or(body);

    if let Some(ct) = content_type {
        if is_binary_content_type(ct) {
            let ct_lower = ct.to_lowercase();
            let mime = ct_lower.split(';').next().unwrap_or("").trim();
            if mime.starts_with("image/")
                || mime.starts_with("video/")
                || mime.starts_with("audio/")
            {
                if data.len() < 5 * 1024 * 1024 {
                    use base64::{engine::general_purpose, Engine as _};
                    let b64 = general_purpose::STANDARD.encode(data);
                    return Some(format!("__BASE64__:{}:{}", mime, b64));
                } else {
                    let size = format_size(body.len());
                    return Some(format!("[Media too large to preview — {}]", size));
                }
            } else {
                let size_str = format_size(body.len());
                let preview_len = data.len().min(10 * 1024);
                let hex_str = hex::encode(&data[..preview_len]);
                return Some(format!("__HEX__:{}:{}", size_str, hex_str));
            }
        }
    }

    let slice = if data.len() > MAX_BODY_UI {
        &data[..MAX_BODY_UI]
    } else {
        data
    };

    let text = String::from_utf8_lossy(slice);
    let replacement_count = text.chars().filter(|&c| c == '\u{FFFD}').count();
    let total_chars = text.len();

    if total_chars > 0 && replacement_count * 10 > total_chars {
        let size = format_size(body.len());
        let preview_len = data.len().min(10 * 1024);
        let hex_str = hex::encode(&data[..preview_len]);
        Some(format!("__HEX__:{}:{}", size, hex_str))
    } else {
        Some(text.into_owned())
    }
}

fn decompress_gzip(data: &[u8]) -> Option<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .take(MAX_BODY_UI as u64 * 2)
        .read_to_end(&mut result)
        .ok()?;
    Some(result)
}

fn decompress_deflate(data: &[u8]) -> Option<Vec<u8>> {
    let decoder = flate2::read::ZlibDecoder::new(data);
    let mut result = Vec::new();
    if decoder
        .take(MAX_BODY_UI as u64 * 2)
        .read_to_end(&mut result)
        .is_ok()
    {
        return Some(result);
    }
    let decoder = flate2::read::DeflateDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .take(MAX_BODY_UI as u64 * 2)
        .read_to_end(&mut result)
        .ok()?;
    Some(result)
}

fn decompress_brotli(data: &[u8]) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let reader = brotli::Decompressor::new(data, 4096);
    reader
        .take(MAX_BODY_UI as u64 * 2)
        .read_to_end(&mut result)
        .ok()?;
    Some(result)
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
