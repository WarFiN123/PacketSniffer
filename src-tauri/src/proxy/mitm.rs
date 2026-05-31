// ─── MITM TLS Interception ───────────────────────────────────────────────────
// Handles a CONNECT-tunneled connection:
// 1. TLS handshake with client using per-host cert (ALPN: h2, http/1.1)
// 2. Serve HTTP requests from the client via hyper (HTTP/1.1 or HTTP/2)
// 3. Forward each request to the real upstream server via TLS + hyper
// 4. Stream response body back to client in real-time (no full-body buffering)
// 5. Capture up to 256 KB of response body for the UI asynchronously
// 6. WebSocket upgrades (wss://) are detected and relayed via ws.rs

use super::ca::CertificateAuthority;
use super::http::{self, HttpHeader, HttpSession};
use super::intercept::{self, MapKind};
use super::ws::{self, WsMessage};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls::ClientConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ─── Boxed body type for streaming responses ────────────────────────────────

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(data: Bytes) -> BoxBody {
    Full::new(data).map_err(|_| unreachable!()).boxed()
}

fn stream_body(rx: mpsc::Receiver<Result<Frame<Bytes>, hyper::Error>>) -> BoxBody {
    StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)).boxed()
}

/// Perform MITM on a CONNECT tunnel.
/// `stream` is the raw IO after the CONNECT 200 upgrade.
pub async fn handle_connect<S>(
    stream: S,
    hostname: String,
    port: u16,
    ca: Arc<CertificateAuthority>,
    next_id: Arc<AtomicU64>,
    on_event: Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: Arc<dyn Fn(WsMessage) + Send + Sync>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if let Err(e) = handle_connect_inner(
        stream, &hostname, port, &ca, &next_id, &on_event, &on_ws_message,
    )
    .await
    {
        log::debug!("MITM tunnel for {} ended: {}", hostname, e);
    }
}

async fn handle_connect_inner<S>(
    stream: S,
    hostname: &str,
    port: u16,
    ca: &CertificateAuthority,
    next_id: &Arc<AtomicU64>,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: &Arc<dyn Fn(WsMessage) + Send + Sync>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // ── 1. TLS handshake with the client (proxy acts as server) ─────────
    let server_config = ca.server_config_for_host(hostname)?;
    let acceptor = TlsAcceptor::from(server_config);
    let tls_stream = acceptor.accept(stream).await?;

    // Check negotiated ALPN protocol
    let alpn = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
    let is_h2 = alpn.as_deref() == Some(b"h2");

    log::debug!(
        "MITM TLS for {}, client ALPN: {}",
        hostname,
        if is_h2 { "h2" } else { "http/1.1" }
    );

    // ── 2. Serve HTTP requests from the client ──────────────────────────
    if is_h2 {
        serve_h2(tls_stream, hostname, port, next_id, on_event, on_ws_message).await
    } else {
        serve_h1(tls_stream, hostname, port, next_id, on_event, on_ws_message).await
    }
}

// ─── HTTP/1.1 server on MITM'd TLS stream ──────────────────────────────────

async fn serve_h1<IO>(
    tls_stream: tokio_rustls::server::TlsStream<IO>,
    hostname: &str,
    port: u16,
    next_id: &Arc<AtomicU64>,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: &Arc<dyn Fn(WsMessage) + Send + Sync>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(tls_stream);
    let hostname = Arc::new(hostname.to_string());
    let next_id = Arc::clone(next_id);
    let on_event = Arc::clone(on_event);
    let on_ws_message = Arc::clone(on_ws_message);

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(false)
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let hostname = Arc::clone(&hostname);
                let next_id = Arc::clone(&next_id);
                let on_event = Arc::clone(&on_event);
                let on_ws_message = Arc::clone(&on_ws_message);
                async move {
                    handle_mitm_request(req, &hostname, port, &next_id, &on_event, &on_ws_message).await
                }
            }),
        )
        .with_upgrades()
        .await?;

    Ok(())
}

// ─── HTTP/2 server on MITM'd TLS stream ────────────────────────────────────

async fn serve_h2<IO>(
    tls_stream: tokio_rustls::server::TlsStream<IO>,
    hostname: &str,
    port: u16,
    next_id: &Arc<AtomicU64>,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    _on_ws_message: &Arc<dyn Fn(WsMessage) + Send + Sync>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(tls_stream);
    let hostname = Arc::new(hostname.to_string());
    let next_id = Arc::clone(next_id);
    let on_event = Arc::clone(on_event);

    hyper::server::conn::http2::Builder::new(TokioExecutor)
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let hostname = Arc::clone(&hostname);
                let next_id = Arc::clone(&next_id);
                let on_event = Arc::clone(&on_event);
                async move {
                    handle_mitm_h2_request(req, &hostname, port, &next_id, &on_event).await
                }
            }),
        )
        .await?;

    Ok(())
}

// ─── Request handler (HTTP/1.1 client-facing) ──────────────────────────────

async fn handle_mitm_request(
    req: Request<Incoming>,
    hostname: &str,
    port: u16,
    next_id: &Arc<AtomicU64>,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: &Arc<dyn Fn(WsMessage) + Send + Sync>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let is_ws = http::is_websocket_upgrade(req.headers());

    if is_ws {
        handle_mitm_ws(req, hostname, port, next_id, on_event, on_ws_message).await
    } else {
        handle_mitm_normal(req, hostname, port, next_id, on_event).await
    }
}

// ─── Normal HTTPS request (h1 client-facing) ───────────────────────────────

async fn handle_mitm_normal(
    req: Request<Incoming>,
    hostname: &str,
    port: u16,
    next_id: &Arc<AtomicU64>,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let session_id = next_id.fetch_add(1, Ordering::Relaxed);
    let method = req.method().to_string();
    let uri = req.uri().clone();
    let version = req.version();
    let req_headers_ui = http::headers_from_hyper(req.headers());
    // Keep the raw HeaderMap for lossless forwarding to upstream
    let raw_headers = req.headers().clone();

    let host = raw_headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(hostname)
        .to_string();

    let path = uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());

    // Collect request body
    let req_body = req.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let req_body_for_session = if req_body.is_empty() { None } else { Some(req_body.to_vec()) };

    let session = HttpSession::new_request(
        session_id, "https", &method, &host, &path, &path,
        http::version_str(version), req_headers_ui,
        req_body.len(), req_body_for_session,
    );
    on_event("start", session.clone());
    let start = std::time::Instant::now();

    // ── Interception: block / allow + request mapping ───────────────────
    let full_url = format!("https://{}{}", host, path);
    if intercept::is_blocked(&full_url) {
        let mut s = session;
        s.finish(403, "Blocked", "HTTP/1.1", "text/plain", 0, ms(&start), Vec::new(),
            Some(b"Blocked by PacketSniffer".to_vec()));
        on_event("finish", s);
        return Ok(err_resp(403, "Blocked by PacketSniffer"));
    }

    let (mut eff_host, mut eff_port, mut eff_path) =
        (hostname.to_string(), port, path.clone());
    if let Some((kind, target)) = intercept::map_for(&full_url) {
        match kind {
            MapKind::Local => {
                return Ok(serve_map_local_box(&target, session, &start, on_event).await);
            }
            MapKind::Remote => {
                // Only https:// targets are supported on the TLS path.
                if let Some((h, p, pth)) = parse_https_target(&target) {
                    eff_host = h;
                    eff_port = p;
                    eff_path = pth;
                }
            }
        }
    }

    // Connect upstream TLS
    let tls_stream = match connect_upstream_tls(&eff_host, eff_port).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Upstream TLS failed for {}:{}: {}", eff_host, eff_port, e);
            let mut s = session;
            s.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
            on_event("finish", s);
            return Ok(err_resp(502, &format!("Bad Gateway: {}", e)));
        }
    };

    // Check upstream ALPN
    let upstream_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");

    if upstream_h2 {
        forward_h2(tls_stream, &method, &eff_path, &eff_host, eff_port, &raw_headers, req_body, session, start, on_event).await
    } else {
        forward_h1(tls_stream, &method, &eff_path, &raw_headers, req_body, session, start, &eff_host, on_event).await
    }
}

// ─── Request handler (HTTP/2 client-facing) ────────────────────────────────

async fn handle_mitm_h2_request(
    req: Request<Incoming>,
    hostname: &str,
    port: u16,
    next_id: &Arc<AtomicU64>,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let session_id = next_id.fetch_add(1, Ordering::Relaxed);
    let method = req.method().to_string();
    let uri = req.uri().clone();
    let version = req.version();
    let req_headers_ui = http::headers_from_hyper(req.headers());
    let raw_headers = req.headers().clone();

    let host = raw_headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            raw_headers
                .get(":authority")
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or(hostname)
        .to_string();

    let path = uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());

    let req_body = req.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let req_body_for_session = if req_body.is_empty() { None } else { Some(req_body.to_vec()) };

    let session = HttpSession::new_request(
        session_id, "https", &method, &host, &path, &path,
        http::version_str(version), req_headers_ui,
        req_body.len(), req_body_for_session,
    );
    on_event("start", session.clone());
    let start = std::time::Instant::now();

    // ── Interception: block / allow + request mapping ───────────────────
    let full_url = format!("https://{}{}", host, path);
    if intercept::is_blocked(&full_url) {
        let mut s = session;
        s.finish(403, "Blocked", "HTTP/1.1", "text/plain", 0, ms(&start), Vec::new(),
            Some(b"Blocked by PacketSniffer".to_vec()));
        on_event("finish", s);
        return Ok(err_resp(403, "Blocked by PacketSniffer"));
    }

    let (mut eff_host, mut eff_port, mut eff_path) =
        (hostname.to_string(), port, path.clone());
    if let Some((kind, target)) = intercept::map_for(&full_url) {
        match kind {
            MapKind::Local => {
                return Ok(serve_map_local_box(&target, session, &start, on_event).await);
            }
            MapKind::Remote => {
                if let Some((h, p, pth)) = parse_https_target(&target) {
                    eff_host = h;
                    eff_port = p;
                    eff_path = pth;
                }
            }
        }
    }

    let tls_stream = match connect_upstream_tls(&eff_host, eff_port).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Upstream TLS failed for {}:{}: {}", eff_host, eff_port, e);
            let mut s = session;
            s.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
            on_event("finish", s);
            return Ok(err_resp(502, &format!("Bad Gateway: {}", e)));
        }
    };

    let upstream_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");

    if upstream_h2 {
        forward_h2(tls_stream, &method, &eff_path, &eff_host, eff_port, &raw_headers, req_body, session, start, on_event).await
    } else {
        forward_h1(tls_stream, &method, &eff_path, &raw_headers, req_body, session, start, &eff_host, on_event).await
    }
}

// ─── WebSocket upgrade over MITM (wss://) ──────────────────────────────────

async fn handle_mitm_ws(
    req: Request<Incoming>,
    hostname: &str,
    port: u16,
    next_id: &Arc<AtomicU64>,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: &Arc<dyn Fn(WsMessage) + Send + Sync>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let session_id = next_id.fetch_add(1, Ordering::Relaxed);
    let method = req.method().to_string();
    let uri = req.uri().clone();
    let version = req.version();
    let req_headers = http::headers_from_hyper(req.headers());

    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(hostname)
        .to_string();

    let path = uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());

    // Extract the upgrade future BEFORE consuming the request body.
    let upgrade_fut = hyper::upgrade::on(req);

    let mut session = HttpSession::new_request(
        session_id, "wss", &method, &host, &path, &path,
        http::version_str(version), req_headers.clone(), 0, None,
    );
    on_event("start", session.clone());
    let start = std::time::Instant::now();

    // Connect upstream TLS — force HTTP/1.1 ALPN for WebSocket upgrades
    let mut tls_stream = match connect_upstream_tls_h1(hostname, port).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Upstream TLS for wss:// failed {}:{}: {}", hostname, port, e);
            session.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
            on_event("finish", session);
            return Ok(err_resp(502, &format!("Bad Gateway: {}", e)));
        }
    };

    // Send raw HTTP upgrade request to upstream
    let mut raw_req = format!("{} {} HTTP/1.1\r\n", method, path);
    for h in &req_headers {
        raw_req.push_str(&format!("{}: {}\r\n", h.name, h.value));
    }
    raw_req.push_str("\r\n");

    if tls_stream.write_all(raw_req.as_bytes()).await.is_err() {
        session.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
        on_event("finish", session);
        return Ok(err_resp(502, "Write to upstream failed"));
    }

    // Read 101 response from upstream
    let mut resp_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        match tls_stream.read(&mut tmp).await {
            Ok(0) => {
                session.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
                on_event("finish", session);
                return Ok(err_resp(502, "Upstream closed before WS 101"));
            }
            Ok(n) => {
                resp_buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_header_end(&resp_buf) {
                    header_end = pos;
                    break;
                }
            }
            Err(e) => {
                session.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
                on_event("finish", session);
                return Ok(err_resp(502, &format!("Read error: {}", e)));
            }
        }
    }

    // Parse response
    let mut hdr_buf = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut hdr_buf);
    if parsed.parse(&resp_buf).is_err() {
        session.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
        on_event("finish", session);
        return Ok(err_resp(502, "Parse error on WS 101"));
    }

    let status = parsed.code.unwrap_or(0);
    let status_text = parsed.reason.unwrap_or("").to_string();
    let resp_headers: Vec<HttpHeader> = parsed
        .headers
        .iter()
        .map(|h| HttpHeader {
            name: h.name.to_string(),
            value: String::from_utf8_lossy(h.value).to_string(),
        })
        .collect();

    let content_type = http::find_header(&resp_headers, "Content-Type").unwrap_or("").to_string();
    session.finish(
        status, &status_text, "HTTP/1.1", &content_type,
        header_end, ms(&start), resp_headers.clone(), None,
    );
    on_event("finish", session);

    if status != 101 {
        log::warn!("WS upgrade rejected by {} with status {}", hostname, status);
        let mut resp = Response::builder().status(status);
        for h in &resp_headers {
            if let (Ok(n), Ok(v)) = (
                hyper::header::HeaderName::from_bytes(h.name.as_bytes()),
                hyper::header::HeaderValue::from_str(&h.value),
            ) {
                resp = resp.header(n, v);
            }
        }
        return Ok(resp.body(full_body(Bytes::from(resp_buf[header_end..].to_vec()))).unwrap());
    }

    log::info!("WebSocket upgrade succeeded for wss://{}{}", hostname, path);

    // Extra bytes after 101 headers are early WS frames from upstream
    let extra = if header_end < resp_buf.len() {
        Some(resp_buf[header_end..].to_vec())
    } else {
        None
    };

    // Spawn the WS relay task.
    let on_ws = Arc::clone(on_ws_message);
    tokio::spawn(async move {
        match upgrade_fut.await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);

                // Forward any early upstream WS frames to the client
                if let Some(ref extra_bytes) = extra {
                    if client_io.write_all(extra_bytes).await.is_err() {
                        return;
                    }
                }

                let (cr, cw) = tokio::io::split(client_io);
                let (rr, rw) = tokio::io::split(tls_stream);

                ws::relay_websocket(cr, cw, rr, rw, session_id, on_ws).await;
            }
            Err(e) => log::error!("WS client upgrade failed: {}", e),
        }
    });

    // Build 101 response for the client
    let mut resp = Response::builder().status(101);
    for h in &resp_headers {
        if let (Ok(n), Ok(v)) = (
            hyper::header::HeaderName::from_bytes(h.name.as_bytes()),
            hyper::header::HeaderValue::from_str(&h.value),
        ) {
            resp = resp.header(n, v);
        }
    }
    Ok(resp.body(full_body(Bytes::new())).unwrap())
}

// ─── Upstream forwarding ────────────────────────────────────────────────────

async fn forward_h1(
    tls_stream: tokio_rustls::client::TlsStream<TcpStream>,
    method: &str,
    path: &str,
    raw_headers: &hyper::header::HeaderMap,
    req_body: Bytes,
    session: HttpSession,
    start: std::time::Instant,
    hostname: &str,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(p) => p,
        Err(e) => {
            log::error!("Upstream h1 handshake failed {}: {}", hostname, e);
            let mut s = session;
            s.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
            on_event("finish", s);
            return Ok(err_resp(502, &format!("Handshake: {}", e)));
        }
    };

    tokio::spawn(async move { let _ = conn.await; });

    let mut builder = Request::builder().method(method).uri(path).version(hyper::Version::HTTP_11);

    // Forward headers directly from the raw HeaderMap — lossless, preserves
    // non-visible-ASCII bytes in cookie/auth values that to_str() would reject.
    // Host is set explicitly below so remote-mapped requests target the new
    // host (for normal requests `hostname` equals the original host).
    let no_cache = intercept::no_cache();
    for (name, value) in raw_headers.iter() {
        let name_str = name.as_str();
        // Strip hop-by-hop and framing headers. hyper sets Content-Length
        // automatically from the Full<Bytes> body.
        if name_str.eq_ignore_ascii_case("transfer-encoding")
            || name_str.eq_ignore_ascii_case("content-length")
            || name_str.eq_ignore_ascii_case("connection")
            || name_str.eq_ignore_ascii_case("keep-alive")
            || name_str.eq_ignore_ascii_case("proxy-connection")
            || name_str.eq_ignore_ascii_case("proxy-authorization")
            || name_str.eq_ignore_ascii_case("host")
        {
            continue;
        }
        // No-Cache: drop conditional headers so the server returns a fresh 200.
        if no_cache && intercept::is_conditional_header(name_str) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    builder = builder.header("host", hostname);

    let upstream_req = builder.body(Full::new(req_body)).unwrap();
    match sender.send_request(upstream_req).await {
        Ok(resp) => stream_response(resp, session, start, on_event).await,
        Err(e) => {
            let mut s = session;
            s.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
            on_event("finish", s);
            Ok(err_resp(502, &format!("Request: {}", e)))
        }
    }
}

async fn forward_h2(
    tls_stream: tokio_rustls::client::TlsStream<TcpStream>,
    method: &str,
    path: &str,
    hostname: &str,
    port: u16,
    raw_headers: &hyper::header::HeaderMap,
    req_body: Bytes,
    session: HttpSession,
    start: std::time::Instant,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = match hyper::client::conn::http2::handshake(TokioExecutor, io).await {
        Ok(p) => p,
        Err(e) => {
            log::error!("Upstream h2 handshake failed: {}", e);
            let mut s = session;
            s.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
            on_event("finish", s);
            return Ok(err_resp(502, &format!("H2 handshake: {}", e)));
        }
    };

    tokio::spawn(async move { let _ = conn.await; });

    // HTTP/2 requires a full URI with scheme + authority for the pseudo-headers
    let full_uri = if port == 443 {
        format!("https://{}{}", hostname, path)
    } else {
        format!("https://{}:{}{}", hostname, port, path)
    };

    let mut builder = Request::builder().method(method).uri(&full_uri);
    let no_cache = intercept::no_cache();
    for (name, value) in raw_headers.iter() {
        let name_str = name.as_str();
        // Skip hop-by-hop and framing headers invalid in HTTP/2
        if name_str.eq_ignore_ascii_case("connection")
            || name_str.eq_ignore_ascii_case("transfer-encoding")
            || name_str.eq_ignore_ascii_case("content-length")
            || name_str.eq_ignore_ascii_case("keep-alive")
            || name_str.eq_ignore_ascii_case("upgrade")
            || name_str.eq_ignore_ascii_case("proxy-connection")
            || name_str.eq_ignore_ascii_case("proxy-authorization")
            || name_str.eq_ignore_ascii_case("host") // :authority replaces Host in h2
        {
            continue;
        }
        if no_cache && intercept::is_conditional_header(name_str) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }

    let upstream_req = builder.body(Full::new(req_body)).unwrap();
    match sender.send_request(upstream_req).await {
        Ok(resp) => stream_response(resp, session, start, on_event).await,
        Err(e) => {
            let mut s = session;
            s.finish(0, "", "", "", 0, ms(&start), Vec::new(), None);
            on_event("finish", s);
            Ok(err_resp(502, &format!("Request: {}", e)))
        }
    }
}

/// Stream the upstream response body to the client in real-time.
/// Instead of buffering the entire body, we:
/// 1. Immediately return response headers + a streaming body channel
/// 2. Spawn a background task that reads chunks from upstream and forwards them
/// 3. Capture up to MAX_CAPTURE bytes for the UI session
/// 4. Emit "finish" event once the body is fully streamed
async fn stream_response(
    resp: Response<Incoming>,
    session: HttpSession,
    start: std::time::Instant,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let status = resp.status().as_u16();
    let status_text = resp.status().canonical_reason().unwrap_or("").to_string();
    let version = resp.version();
    let raw_resp_headers = resp.headers().clone();
    let headers = http::headers_from_hyper(&raw_resp_headers);
    let ct = http::find_header(&headers, "content-type").unwrap_or("").to_string();

    // Network-condition simulation (added latency + download throttle).
    let (latency_ms, kbps) = intercept::throttle();

    // Create a channel for streaming body to the client
    // Buffer of 64 frames to avoid back-pressure stalling the upstream read
    let (body_tx, body_rx) = mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(64);

    // Build the response for the client immediately (headers only, body streams)
    // Use raw HeaderMap for lossless forwarding
    let mut client_resp = Response::builder().status(status);
    for (name, value) in raw_resp_headers.iter() {
        if name.as_str().eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        client_resp = client_resp.header(name.clone(), value.clone());
    }

    // Spawn background task to stream body chunks
    let on_event = Arc::clone(on_event);
    tokio::spawn(async move {
        const MAX_CAPTURE: usize = 256 * 1024; // 256 KB for UI
        let mut captured: Vec<u8> = Vec::new();
        let mut total_size: usize = 0;
        let mut session = session;

        let mut body = resp.into_body();

        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        let chunk_len = data.len();
                        total_size += chunk_len;

                        // Capture up to MAX_CAPTURE for the UI
                        if captured.len() < MAX_CAPTURE {
                            let remaining = MAX_CAPTURE - captured.len();
                            let take = chunk_len.min(remaining);
                            captured.extend_from_slice(&data[..take]);
                        }

                        // Forward the frame to the client
                        if body_tx.send(Ok(Frame::data(data.clone()))).await.is_err() {
                            // Client disconnected
                            log::debug!("Client disconnected during body stream for {}{}", session.host, session.path);
                            break;
                        }

                        // Bandwidth throttle: pace delivery by chunk size.
                        if kbps > 0 {
                            let pace_ms = ((chunk_len as u64) * 8) / (kbps as u64).max(1);
                            if pace_ms > 0 {
                                tokio::time::sleep(std::time::Duration::from_millis(pace_ms)).await;
                            }
                        }
                    } else if frame.is_trailers() {
                        // Forward trailers
                        let _ = body_tx.send(Ok(frame)).await;
                    }
                }
                Some(Err(e)) => {
                    log::error!("Upstream body read error for {}{}: {}", session.host, session.path, e);
                    break;
                }
                None => {
                    // Body complete
                    break;
                }
            }
        }

        // Drop the sender to signal end-of-body to the client
        drop(body_tx);

        // Emit finish event with captured body
        let body_for_session = if captured.is_empty() { None } else { Some(captured) };
        session.finish(
            status, &status_text, http::version_str(version), &ct,
            total_size, ms(&start), headers, body_for_session,
        );
        log::info!(
            "MITM {} {} {} -> {} ({} bytes, {:.0}ms, {})",
            session.method, session.host, session.path,
            status, total_size, ms(&start), http::version_str(version),
        );
        on_event("finish", session);
    });

    // Latency simulation: hold the response headers before delivery.
    if latency_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(latency_ms)).await;
    }

    Ok(client_resp.body(stream_body(body_rx)).unwrap())
}

// ─── Upstream TLS connection ────────────────────────────────────────────────

async fn connect_upstream_tls(
    hostname: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    connect_upstream_tls_with_alpn(hostname, port, vec![b"h2".to_vec(), b"http/1.1".to_vec()]).await
}

/// Connect upstream TLS with HTTP/1.1-only ALPN — required for WebSocket
/// upgrades, which are always HTTP/1.1 and would break if the server
/// negotiates h2.
async fn connect_upstream_tls_h1(
    hostname: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    connect_upstream_tls_with_alpn(hostname, port, vec![b"http/1.1".to_vec()]).await
}

async fn connect_upstream_tls_with_alpn(
    hostname: &str,
    port: u16,
    alpn: Vec<Vec<u8>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let tcp = TcpStream::connect(format!("{}:{}", hostname, port)).await?;

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = alpn;

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())?;
    let tls = connector.connect(server_name, tcp).await?;

    Ok(tls)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn ms(start: &std::time::Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn err_resp(status: u16, msg: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .body(full_body(Bytes::from(msg.to_string())))
        .unwrap()
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Serve a local file in place of the upstream response (Map Local rule).
async fn serve_map_local_box(
    path: &str,
    mut session: HttpSession,
    start: &std::time::Instant,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
) -> Response<BoxBody> {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let ct = intercept::guess_content_type(path);
            let headers = vec![
                HttpHeader { name: "Content-Type".to_string(), value: ct.to_string() },
                HttpHeader { name: "Content-Length".to_string(), value: bytes.len().to_string() },
                HttpHeader { name: "X-PacketSniffer-Map".to_string(), value: "local".to_string() },
            ];
            session.finish(200, "OK", "HTTP/1.1", ct, bytes.len(),
                ms(start), headers.clone(), Some(bytes.clone()));
            on_event("finish", session);
            intercept::apply_throttle_total(bytes.len()).await;

            let mut resp = Response::builder().status(200);
            for h in &headers {
                if let (Ok(n), Ok(v)) = (
                    hyper::header::HeaderName::from_bytes(h.name.as_bytes()),
                    hyper::header::HeaderValue::from_str(&h.value),
                ) {
                    resp = resp.header(n, v);
                }
            }
            resp.body(full_body(Bytes::from(bytes))).unwrap()
        }
        Err(e) => {
            let msg = format!("Map Local file error: {}", e);
            session.finish(502, "Bad Gateway", "HTTP/1.1", "text/plain", 0,
                ms(start), Vec::new(), Some(msg.clone().into_bytes()));
            on_event("finish", session);
            err_resp(502, &msg)
        }
    }
}

/// Parse an `https://host[:port]/path` Map Remote target. Returns `None` for
/// non-https targets (the TLS path can't downgrade to plaintext).
fn parse_https_target(target: &str) -> Option<(String, u16, String)> {
    let rest = target.trim().strip_prefix("https://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(443)),
        None => (authority.to_string(), 443),
    };
    if host.is_empty() {
        None
    } else {
        Some((host, port, path))
    }
}

// ─── Tokio executor for hyper ───────────────────────────────────────────────

#[derive(Clone, Copy)]
struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

// ─── NoVerify: accept any upstream server certificate ───────────────────────

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
