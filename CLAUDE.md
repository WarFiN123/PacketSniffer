# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Tauri v2 desktop MITM proxy inspector (Proxyman-inspired). Captures HTTP/HTTPS/WebSocket traffic with full SSL decryption. Frontend: React 19 + TypeScript + Vite. Backend: Rust (hyper, rustls, rcgen).

## Commands

```
bun dev           # Full dev (Tauri + Vite hot-reload)
bun run build     # Production binary
bun run vite:dev  # Frontend only (no Tauri shell)
```

Rust backend only: `cd src-tauri && cargo build` / `cargo check`.

No test suite or lint script configured (`package.json` has no `test`/`lint` entry; no `#[cfg(test)]` modules in `src-tauri/src`). Use `cargo check` / `bun run vite:build` (runs `tsc`) to catch type errors.

## Architecture

### IPC Contract

Frontend and backend share two data shapes — keep them in sync:

- **`HttpSession`** (`src/types.ts` ↔ serde in `proxy/http.rs`): Bodies are **stripped** on the event stream (`metadata_clone()`). Frontend fetches full bodies on-demand via `get_session(id)` Tauri command.
- **`InterceptConfig`** (`src/lib/intercept.ts` ↔ `proxy/intercept.rs`): serde `camelCase`. Shape must match exactly.

### Event Flow

```
TCP accept (engine.rs)
  ├─ plain HTTP → forward + emit proxy-session event (slim metadata)
  ├─ CONNECT    → TLS handshake (ca.rs issues per-host cert) → mitm.rs
  │              → HTTP/1.1 or HTTP/2 → capture bodies → emit proxy-session
  └─ WebSocket  → ws.rs frame relay → emit ws-message events
```

Frontend (`useTauriEvents.ts`) batches `proxy-session` events per animation frame to avoid render thrashing under load.

### Session Store

Bounded at `MAX_SESSIONS = 5000` (defined in `lib.rs` and mirrored in `useTauriEvents.ts` — **must match**). Bodies retained server-side, truncated at 256 KB for UI transport. Oldest evicted when full.

### Key Modules

| File | Role |
|------|------|
| `src-tauri/src/lib.rs` | All Tauri commands + event emitters |
| `src-tauri/src/proxy/engine.rs` | TCP listener, request routing |
| `src-tauri/src/proxy/mitm.rs` | TLS MITM, HTTP/1.1 + HTTP/2 interception |
| `src-tauri/src/proxy/ca.rs` | Root CA + per-host cert generation (cached by hostname) |
| `src-tauri/src/proxy/intercept.rs` | Process-global intercept rules (RwLock) |
| `src-tauri/src/system_proxy.rs` | OS proxy registry (Windows/macOS/Linux) |
| `src-tauri/src/cert_store.rs` | OS trust store check + CA install. On Linux also writes each browser's NSS DB — see "Browser trust on Linux" |
| `src-tauri/src/apk.rs` | Android MITM: repatches APKs (apktool) to trust the proxy CA via injected `network_security_config.xml`, re-signs (zipalign/apksigner); requires java/keytool/apktool/zipalign/apksigner/adb on PATH |
| `src/App.tsx` | Root layout, top-level state |
| `src/hooks/useTauriEvents.ts` | Event batching, session map, WS message map |
| `src/types.ts` | Shared TS interfaces |

### Frontend State

All session state lives in `App.tsx` via `useProxySessions()` and `useWsMessages()` hooks from `useTauriEvents.ts`. Components receive filtered/derived data as props — no global store.

## Key Invariants

- `MAX_SESSIONS` constant must be identical in `lib.rs` and `useTauriEvents.ts`.
- `InterceptConfig` field names must match between `intercept.rs` (serde rename `camelCase`) and `src/lib/intercept.ts`.
- Bodies are never in the streamed event — always fetch via `get_session()`.
- CA cert lives at `{app_data}/ca-cert.pem` / `ca-key.pem`, gated by a `ca-version` file (`CA_VERSION` in `ca.rs` — bump it to force regeneration). Per-host certs are in-memory only, cached in a `ServerConfig` map inside `ca.rs`.
- System proxy is restored on `stop_proxy()` and also on startup (stale cleanup for crash recovery).

### Browser trust on Linux

`security.enterprise_roots.enabled` is implemented only for Windows and macOS. A CA in `/etc/ssl` is therefore **invisible to Firefox and Chromium on Linux** — every HTTPS page fails with `MOZILLA_PKIX_ERROR_MITM_DETECTED` (Firefox's rename of `SEC_ERROR_UNKNOWN_ISSUER`, triggered when its MITM canary probe returns a cert from the same unknown root). Writing `security.enterprise_roots.enabled` into a profile's `user.js` does nothing there.

So `ensure_trusted_linux` does three things, and dropping any one of them reintroduces the bug:

1. **System anchor** — distro-detected (`trust_store()`: Debian / Fedora / openSUSE / Arch each use a different anchor dir and refresh command). Serves curl, git, python; not browsers.
2. **NSS databases** — `certutil -A -t CT,,` into every profile found via `profiles.ini` across native, Snap and Flatpak installs, plus `~/.pki/nssdb` for the Chromium family. This is what actually fixes the browsers, and it needs `certutil` from libnss3-tools.
3. **`policies.json`** — merged, never overwritten, so distro/enterprise policies survive. Covers profiles created later.

Steps 1 and 3 need root and share **one** `pkexec` call — keep it that way; splitting it means a password prompt per file. Never write to `/snap/firefox/...` (read-only squashfs); the Snap reads `/etc/firefox/policies` instead.
