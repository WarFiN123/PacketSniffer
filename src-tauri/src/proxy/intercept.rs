// ─── Interception Rules ──────────────────────────────────────────────────────
// Process-global config for No-Cache, Block/Allow lists, request mapping, and
// network throttling. There is a single proxy engine per app, so a global lets
// the hot request path consult the rules without threading a handle through
// every function signature in engine.rs / mitm.rs.

use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ListMode {
    #[default]
    Off,
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MapKind {
    Local,
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MapRule {
    pub pattern: String,
    pub kind: MapKind,
    pub target: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InterceptConfig {
    /// Strip conditional-request headers so servers return fresh 200s, not 304s.
    pub no_cache: bool,
    pub list_mode: ListMode,
    /// Wildcard patterns matched against the full request URL.
    pub list_rules: Vec<String>,
    pub map_rules: Vec<MapRule>,
    /// Added delay before the response is delivered (network latency sim).
    pub latency_ms: u64,
    /// Download throttle in kilobits/sec; 0 means unlimited.
    pub kbps: u32,
}

static CONFIG: LazyLock<RwLock<InterceptConfig>> =
    LazyLock::new(|| RwLock::new(InterceptConfig::default()));

pub fn get() -> InterceptConfig {
    CONFIG.read().unwrap().clone()
}

pub fn set(cfg: InterceptConfig) {
    *CONFIG.write().unwrap() = cfg;
}

pub fn no_cache() -> bool {
    CONFIG.read().unwrap().no_cache
}

/// `(latency_ms, kbps)` — `kbps == 0` means unlimited.
pub fn throttle() -> (u64, u32) {
    let c = CONFIG.read().unwrap();
    (c.latency_ms, c.kbps)
}

/// Whether a request to `url` should be blocked under the current list mode.
pub fn is_blocked(url: &str) -> bool {
    let c = CONFIG.read().unwrap();
    match c.list_mode {
        ListMode::Off => false,
        ListMode::Block => c.list_rules.iter().any(|p| matches(p, url)),
        ListMode::Allow => !c.list_rules.iter().any(|p| matches(p, url)),
    }
}

/// First enabled map rule matching `url`, as `(kind, target)`.
pub fn map_for(url: &str) -> Option<(MapKind, String)> {
    let c = CONFIG.read().unwrap();
    c.map_rules
        .iter()
        .find(|r| r.enabled && !r.target.is_empty() && matches(&r.pattern, url))
        .map(|r| (r.kind, r.target.clone()))
}

/// Conditional-request headers stripped in No-Cache mode (case-insensitive).
pub fn is_conditional_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("if-none-match")
        || name.eq_ignore_ascii_case("if-modified-since")
        || name.eq_ignore_ascii_case("if-range")
        || name.eq_ignore_ascii_case("if-match")
        || name.eq_ignore_ascii_case("if-unmodified-since")
}

/// Wildcard match: `*` matches any run of characters. Case-insensitive. With no
/// `*`, it's a plain substring test. Empty patterns never match.
fn matches(pattern: &str, url: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let p = pattern.to_lowercase();
    let u = url.to_lowercase();

    if !p.contains('*') {
        return u.contains(&p);
    }

    let parts: Vec<&str> = p.split('*').collect();
    let mut idx = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match u[idx..].find(part) {
            Some(pos) => {
                // A leading non-'*' segment must anchor at the start.
                if i == 0 && pos != 0 {
                    return false;
                }
                idx += pos + part.len();
            }
            None => return false,
        }
    }

    // A trailing non-'*' segment must reach the end.
    if !p.ends_with('*') {
        if let Some(last) = parts.last() {
            if !last.is_empty() && !u.ends_with(last) {
                return false;
            }
        }
    }
    true
}

/// Guess a content-type from a file path extension (for Map Local responses).
pub fn guess_content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// Apply latency + bandwidth throttle for a response of `body_len` bytes, all at
/// once (used by the buffered plain-HTTP path). Sleeps `latency + size/kbps`.
pub async fn apply_throttle_total(body_len: usize) {
    let (latency_ms, kbps) = throttle();
    let mut delay_ms = latency_ms;
    if kbps > 0 {
        // bits / (kbits/sec) → ms:  (bytes*8) / (kbps*1000) * 1000
        delay_ms += ((body_len as u64) * 8) / (kbps as u64).max(1);
    }
    if delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }
}
