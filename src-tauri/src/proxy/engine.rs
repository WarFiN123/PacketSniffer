// ─── Proxy Engine ────────────────────────────────────────────────────────────
// Async TCP listener using hyper HTTP/1.1 for the client-facing side.
// - CONNECT: upgrade → raw tunnel → mitm.rs (TLS + HTTP/2 or HTTP/1.1)
// - Plain HTTP: forward upstream via hyper client
// - Plain WS (ws://): upgrade + relay via ws.rs

use super::ca::CertificateAuthority;
use super::http::{self, HttpHeader, HttpSession};
use super::intercept::{self, MapKind};
use super::mitm;
use super::ws::{self, WsMessage};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

pub struct ProxyEngine {
    port: u16,
    stop_tx: Option<watch::Sender<bool>>,
    next_id: Arc<AtomicU64>,
    on_event: Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: Arc<dyn Fn(WsMessage) + Send + Sync>,
}

impl ProxyEngine {
    /// Create a new proxy engine with the given event callbacks.
    pub fn new<F, W>(on_event: F, on_ws_message: W) -> Self
    where
        F: Fn(&str, HttpSession) + Send + Sync + 'static,
        W: Fn(WsMessage) + Send + Sync + 'static,
    {
        Self {
            port: 0,
            stop_tx: None,
            next_id: Arc::new(AtomicU64::new(1)),
            on_event: Arc::new(on_event),
            on_ws_message: Arc::new(on_ws_message),
        }
    }

    pub async fn start(
        &mut self,
        port: u16,
    ) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        let actual_port = listener.local_addr()?.port();
        self.port = actual_port;

        let ca = Arc::new(
            CertificateAuthority::initialize(None)
                .map_err(|e| format!("CA init failed: {}", e))?,
        );

        log::info!("Proxy listening on port {}", actual_port);
        log::info!("CA cert: {}", ca.ca_cert_path().display());

        let (stop_tx, stop_rx) = watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let next_id = Arc::clone(&self.next_id);
        let on_event = Arc::clone(&self.on_event);
        let on_ws_message = Arc::clone(&self.on_ws_message);

        tokio::spawn(async move {
            accept_loop(listener, ca, next_id, on_event, on_ws_message, stop_rx, None).await;
        });

        Ok(actual_port)
    }

    /// Start an extra listener on a free loopback port whose sessions are all
    /// tagged with `tag` (a device label), reusing this engine's CA/callbacks
    /// and id counter. Used for USB `adb reverse` device capture: the peer is
    /// always 127.0.0.1 there, so we can't identify the device by source IP —
    /// the tag stands in. Returns the bound port and a stop handle.
    pub async fn start_tagged(
        &self,
        tag: Arc<str>,
    ) -> Result<(u16, watch::Sender<bool>), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let ca = Arc::new(
            CertificateAuthority::initialize(None)
                .map_err(|e| format!("CA init failed: {}", e))?,
        );
        let (stop_tx, stop_rx) = watch::channel(false);
        let next_id = Arc::clone(&self.next_id);
        let on_event = Arc::clone(&self.on_event);
        let on_ws_message = Arc::clone(&self.on_ws_message);
        tokio::spawn(async move {
            accept_loop(listener, ca, next_id, on_event, on_ws_message, stop_rx, Some(tag)).await;
        });
        log::info!("Device capture listening on 127.0.0.1:{}", port);
        Ok((port, stop_tx))
    }

    pub async fn stop(self) {
        if let Some(tx) = self.stop_tx {
            let _ = tx.send(true);
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

async fn accept_loop(
    listener: TcpListener,
    ca: Arc<CertificateAuthority>,
    next_id: Arc<AtomicU64>,
    on_event: Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: Arc<dyn Fn(WsMessage) + Send + Sync>,
    mut stop_rx: watch::Receiver<bool>,
    tag: Option<Arc<str>>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        let ca = Arc::clone(&ca);
                        let next_id = Arc::clone(&next_id);
                        let on_event = Arc::clone(&on_event);
                        let on_ws_message = Arc::clone(&on_ws_message);
                        // A device listener tags every session with the device
                        // label; the main listener tags with the peer IP so the
                        // UI can tell the host's own traffic from a phone's.
                        let client: Arc<str> = match &tag {
                            Some(t) => Arc::clone(t),
                            None => Arc::from(addr.ip().to_string()),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(stream, client, ca, next_id, on_event, on_ws_message).await {
                                log::debug!("Connection handler error: {}", e);
                            }
                        });
                    }
                    Err(e) => log::error!("Accept error: {}", e),
                }
            }
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    log::info!("Proxy engine shutting down");
                    break;
                }
            }
        }
    }
}

/// Serve one proxy connection with hyper HTTP/1.1.
async fn serve_connection(
    stream: TcpStream,
    client: Arc<str>,
    ca: Arc<CertificateAuthority>,
    next_id: Arc<AtomicU64>,
    on_event: Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: Arc<dyn Fn(WsMessage) + Send + Sync>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(false)
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let client = Arc::clone(&client);
                let ca = Arc::clone(&ca);
                let next_id = Arc::clone(&next_id);
                let on_event = Arc::clone(&on_event);
                let on_ws_message = Arc::clone(&on_ws_message);
                async move {
                    route_request(req, client, ca, next_id, on_event, on_ws_message).await
                }
            }),
        )
        .with_upgrades()
        .await?;

    Ok(())
}

/// Dispatch a request to the appropriate handler.
async fn route_request(
    req: Request<Incoming>,
    client: Arc<str>,
    ca: Arc<CertificateAuthority>,
    next_id: Arc<AtomicU64>,
    on_event: Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: Arc<dyn Fn(WsMessage) + Send + Sync>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        Ok(handle_connect(req, client, ca, next_id, on_event, on_ws_message))
    } else if http::is_websocket_upgrade(req.headers()) {
        Ok(handle_ws_upgrade(req, client, next_id, on_event, on_ws_message).await)
    } else {
        Ok(handle_plain_http(req, client, next_id, on_event).await)
    }
}

// ─── CONNECT Tunnel ─────────────────────────────────────────────────────────

fn handle_connect(
    req: Request<Incoming>,
    client: Arc<str>,
    ca: Arc<CertificateAuthority>,
    next_id: Arc<AtomicU64>,
    on_event: Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: Arc<dyn Fn(WsMessage) + Send + Sync>,
) -> Response<Full<Bytes>> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());
    let (hostname, port) = parse_connect_target(&authority);

    log::debug!("CONNECT tunnel to {}:{}", hostname, port);

    // We must call hyper::upgrade::on(req) BEFORE returning the response.
    // This gives us a future that resolves to the raw upgraded IO once
    // hyper finishes sending our 200 response and releases the transport.
    let upgrade_fut = hyper::upgrade::on(req);

    tokio::spawn(async move {
        match upgrade_fut.await {
            Ok(upgraded) => {
                let stream = TokioIo::new(upgraded);
                mitm::handle_connect(
                    stream, hostname, port, client, ca, next_id, on_event, on_ws_message,
                )
                .await;
            }
            Err(e) => log::error!("CONNECT upgrade failed for {}:{}: {}", hostname, port, e),
        }
    });

    Response::new(Full::new(Bytes::new()))
}

// ─── Plain HTTP Forwarding ──────────────────────────────────────────────────

async fn handle_plain_http(
    req: Request<Incoming>,
    client: Arc<str>,
    next_id: Arc<AtomicU64>,
    on_event: Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
) -> Response<Full<Bytes>> {
    let session_id = next_id.fetch_add(1, Ordering::Relaxed);
    let method = req.method().to_string();
    let uri = req.uri().clone();
    let version = req.version();
    let req_headers = http::headers_from_hyper(req.headers());

    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let path = uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());
    let full_url = uri.to_string();

    // Collect request body
    let req_body_bytes = req.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let req_body_for_session = if req_body_bytes.is_empty() {
        None
    } else {
        Some(req_body_bytes.to_vec())
    };

    let mut session = HttpSession::new_request(
        session_id,
        &client,
        "http",
        &method,
        &host,
        &path,
        &full_url,
        http::version_str(version),
        req_headers.clone(),
        req_body_bytes.len(),
        req_body_for_session,
    );
    on_event("start", session.clone());
    let start_time = std::time::Instant::now();

    // ── Interception: block / allow list ────────────────────────────────
    if intercept::is_blocked(&full_url) {
        session.finish(403, "Blocked", "HTTP/1.1", "text/plain", 0,
            elapsed_ms(&start_time), Vec::new(), Some(b"Blocked by PacketSniffer".to_vec()));
        on_event("finish", session);
        return error_response(403, "Blocked by PacketSniffer");
    }

    // Upstream target defaults to the original host/path; map rules may override.
    let (mut hostname, mut port) = parse_host_port(&host, 80);
    let mut upstream_path = extract_path_from_url(&full_url);

    if let Some((kind, target)) = intercept::map_for(&full_url) {
        match kind {
            MapKind::Local => {
                return serve_map_local_http(&target, &mut session, &start_time, &on_event).await;
            }
            MapKind::Remote => {
                // Only http:// targets are supported on the plain-HTTP path.
                if let Some((h, p, pth)) = parse_http_target(&target) {
                    hostname = h;
                    port = p;
                    upstream_path = pth;
                }
            }
        }
    }

    if hostname.is_empty() {
        session.finish(502, "Bad Gateway", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
        on_event("finish", session);
        return error_response(502, "Bad Gateway: no host");
    }

    // Connect upstream
    let remote_addr = format!("{}:{}", hostname, port);
    let upstream_stream = match TcpStream::connect(&remote_addr).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Upstream connect failed {}: {}", remote_addr, e);
            session.finish(502, "Bad Gateway", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
            on_event("finish", session);
            return error_response(502, &format!("Bad Gateway: {}", e));
        }
    };

    let io = TokioIo::new(upstream_stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(parts) => parts,
        Err(e) => {
            log::error!("Upstream handshake failed {}: {}", remote_addr, e);
            session.finish(502, "Bad Gateway", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
            on_event("finish", session);
            return error_response(502, &format!("Bad Gateway: {}", e));
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("Upstream connection ended: {}", e);
        }
    });

    // Build upstream request with the (possibly remapped) relative path.
    let mut builder = Request::builder()
        .method(method.as_str())
        .uri(&upstream_path)
        .version(hyper::Version::HTTP_11);

    let no_cache = intercept::no_cache();
    for h in &req_headers {
        if h.name.eq_ignore_ascii_case("proxy-connection")
            || h.name.eq_ignore_ascii_case("proxy-authorization")
            // Host is set explicitly below so remote-mapped requests target the
            // new host rather than the original.
            || h.name.eq_ignore_ascii_case("host")
        {
            continue;
        }
        if no_cache && intercept::is_conditional_header(&h.name) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            hyper::header::HeaderName::from_bytes(h.name.as_bytes()),
            hyper::header::HeaderValue::from_str(&h.value),
        ) {
            builder = builder.header(n, v);
        }
    }

    let host_value = if port == 80 {
        hostname.clone()
    } else {
        format!("{}:{}", hostname, port)
    };
    builder = builder.header("host", host_value);

    let upstream_req = builder.body(Full::new(req_body_bytes)).unwrap();

    let upstream_resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("Upstream request failed {}: {}", remote_addr, e);
            session.finish(502, "Bad Gateway", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
            on_event("finish", session);
            return error_response(502, &format!("Bad Gateway: {}", e));
        }
    };

    let resp_status = upstream_resp.status().as_u16();
    let resp_status_text = upstream_resp.status().canonical_reason().unwrap_or("").to_string();
    let resp_version = upstream_resp.version();
    let resp_headers = http::headers_from_hyper(upstream_resp.headers());
    let content_type = http::find_header(&resp_headers, "content-type").unwrap_or("").to_string();

    let resp_body_bytes = upstream_resp.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let resp_body_for_session = if resp_body_bytes.is_empty() {
        None
    } else {
        Some(resp_body_bytes.to_vec())
    };

    session.finish(
        resp_status,
        &resp_status_text,
        http::version_str(resp_version),
        &content_type,
        resp_body_bytes.len(),
        elapsed_ms(&start_time),
        resp_headers.clone(),
        resp_body_for_session,
    );
    on_event("finish", session);

    // Network-condition simulation (latency + bandwidth) for the buffered path.
    intercept::apply_throttle_total(resp_body_bytes.len()).await;
    build_response(resp_status, &resp_headers, resp_body_bytes)
}

// ─── Plain WebSocket Upgrade (ws://) ────────────────────────────────────────

async fn handle_ws_upgrade(
    req: Request<Incoming>,
    client: Arc<str>,
    next_id: Arc<AtomicU64>,
    on_event: Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
    on_ws_message: Arc<dyn Fn(WsMessage) + Send + Sync>,
) -> Response<Full<Bytes>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let session_id = next_id.fetch_add(1, Ordering::Relaxed);
    let method = req.method().to_string();
    let uri = req.uri().clone();
    let version = req.version();
    let req_headers = http::headers_from_hyper(req.headers());

    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let path = uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());
    let full_url = uri.to_string();

    let mut session = HttpSession::new_request(
        session_id, &client, "ws", &method, &host, &path, &full_url,
        http::version_str(version), req_headers.clone(), 0, None,
    );
    on_event("start", session.clone());
    let start_time = std::time::Instant::now();

    let (hostname, port) = parse_host_port(&host, 80);
    if hostname.is_empty() {
        session.finish(502, "Bad Gateway", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
        on_event("finish", session);
        return error_response(502, "Bad Gateway: no host");
    }

    // Connect upstream
    let remote_addr = format!("{}:{}", hostname, port);
    let mut upstream = match TcpStream::connect(&remote_addr).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("WS upstream connect failed {}: {}", remote_addr, e);
            session.finish(502, "Bad Gateway", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
            on_event("finish", session);
            return error_response(502, &format!("Bad Gateway: {}", e));
        }
    };

    // Build raw HTTP upgrade request for upstream
    let upstream_path = extract_path_from_url(&full_url);
    let mut raw_req = format!("{} {} HTTP/1.1\r\n", method, upstream_path);
    for h in &req_headers {
        if h.name.eq_ignore_ascii_case("proxy-connection")
            || h.name.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        raw_req.push_str(&format!("{}: {}\r\n", h.name, h.value));
    }
    raw_req.push_str("\r\n");

    if upstream.write_all(raw_req.as_bytes()).await.is_err() {
        session.finish(502, "Bad Gateway", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
        on_event("finish", session);
        return error_response(502, "Write to upstream failed");
    }

    // Read 101 from upstream
    let mut resp_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let resp_header_end;
    loop {
        match upstream.read(&mut tmp).await {
            Ok(0) => {
                session.finish(0, "", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
                on_event("finish", session);
                return error_response(502, "Upstream closed before WS handshake");
            }
            Ok(n) => {
                resp_buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_header_end(&resp_buf) {
                    resp_header_end = pos;
                    break;
                }
            }
            Err(e) => {
                session.finish(0, "", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
                on_event("finish", session);
                return error_response(502, &format!("Read error: {}", e));
            }
        }
    }

    // Parse upstream response
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers_buf);
    if parsed.parse(&resp_buf).is_err() {
        session.finish(0, "", "", "", 0, elapsed_ms(&start_time), Vec::new(), None);
        on_event("finish", session);
        return error_response(502, "Failed to parse upstream WS response");
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
        resp_header_end, elapsed_ms(&start_time), resp_headers.clone(), None,
    );
    on_event("finish", session);

    if status != 101 {
        log::warn!("WS upgrade rejected by {} with status {}", host, status);
        return build_response_with_body(status, &resp_headers, &resp_buf[resp_header_end..]);
    }

    log::info!("WebSocket upgrade succeeded for ws://{}{}", host, path);

    // Extra bytes after headers are early WS frames from upstream
    let extra = if resp_header_end < resp_buf.len() {
        Some(resp_buf[resp_header_end..].to_vec())
    } else {
        None
    };

    // Get the upgrade future BEFORE returning the 101 response
    let upgrade_fut = hyper::upgrade::on(req);

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

                let (client_read, client_write) = tokio::io::split(client_io);
                let (remote_read, remote_write) = tokio::io::split(upstream);

                ws::relay_websocket(
                    client_read, client_write,
                    remote_read, remote_write,
                    session_id,
                    on_ws_message,
                )
                .await;
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
    resp.body(Full::new(Bytes::new())).unwrap()
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn elapsed_ms(start: &std::time::Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn error_response(status: u16, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap()
}

fn build_response(status: u16, headers: &[HttpHeader], body: Bytes) -> Response<Full<Bytes>> {
    let mut resp = Response::builder().status(status);
    for h in headers {
        if let (Ok(n), Ok(v)) = (
            hyper::header::HeaderName::from_bytes(h.name.as_bytes()),
            hyper::header::HeaderValue::from_str(&h.value),
        ) {
            resp = resp.header(n, v);
        }
    }
    resp.body(Full::new(body)).unwrap()
}

fn build_response_with_body(status: u16, headers: &[HttpHeader], body: &[u8]) -> Response<Full<Bytes>> {
    build_response(status, headers, Bytes::from(body.to_vec()))
}

/// Serve a local file in place of the upstream response (Map Local rule).
async fn serve_map_local_http(
    path: &str,
    session: &mut HttpSession,
    start: &std::time::Instant,
    on_event: &Arc<dyn Fn(&str, HttpSession) + Send + Sync>,
) -> Response<Full<Bytes>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let ct = intercept::guess_content_type(path);
            let headers = vec![
                HttpHeader { name: "Content-Type".to_string(), value: ct.to_string() },
                HttpHeader { name: "Content-Length".to_string(), value: bytes.len().to_string() },
                HttpHeader { name: "X-PacketSniffer-Map".to_string(), value: "local".to_string() },
            ];
            session.finish(200, "OK", "HTTP/1.1", ct, bytes.len(),
                elapsed_ms(start), headers.clone(), Some(bytes.clone()));
            on_event("finish", session.clone());
            intercept::apply_throttle_total(bytes.len()).await;
            build_response(200, &headers, Bytes::from(bytes))
        }
        Err(e) => {
            let msg = format!("Map Local file error: {}", e);
            session.finish(502, "Bad Gateway", "HTTP/1.1", "text/plain", 0,
                elapsed_ms(start), Vec::new(), Some(msg.clone().into_bytes()));
            on_event("finish", session.clone());
            error_response(502, &msg)
        }
    }
}

/// Parse an `http://host[:port]/path` Map Remote target. Returns `None` for
/// non-http targets (the plain-HTTP path can't open a TLS upstream).
fn parse_http_target(target: &str) -> Option<(String, u16, String)> {
    let rest = target.trim().strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        None
    } else {
        Some((host, port, path))
    }
}

fn parse_connect_target(target: &str) -> (String, u16) {
    match target.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>().unwrap_or(443);
            (host.to_string(), port)
        }
        None => (target.to_string(), 443),
    }
}

fn parse_host_port(host_header: &str, default_port: u16) -> (String, u16) {
    match host_header.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>().unwrap_or(default_port);
            (host.to_string(), port)
        }
        None => (host_header.to_string(), default_port),
    }
}

fn extract_path_from_url(url: &str) -> String {
    if let Some(idx) = url.find("://") {
        let after = &url[idx + 3..];
        match after.find('/') {
            Some(slash) => after[slash..].to_string(),
            None => "/".to_string(),
        }
    } else {
        url.to_string()
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}
