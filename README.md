<div align="center">
  <img src="public/logo.png" alt="PacketSniffer logo" width="120" />

  # PacketSniffer

  A Proxyman-inspired MITM proxy inspector built with Tauri v2.

  [![Release](https://img.shields.io/github/v/release/WarFiN123/packetsniffer)](https://github.com/WarFiN123/packetsniffer/releases/latest)
  [![Downloads](https://img.shields.io/github/downloads/WarFiN123/packetsniffer/total)](https://github.com/WarFiN123/packetsniffer/releases)
  [![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)](#)
  ![GitHub Repo stars](https://img.shields.io/github/stars/WarFiN123/PacketSniffer?style=social)
</div>

---

Captures HTTP/HTTPS/WebSocket traffic with full SSL decryption, on Windows/macOS/Linux.

## Features

- HTTP/1.1 and HTTP/2 interception with TLS MITM (per-host certs, cached)
- WebSocket frame capture
- Body viewer/editor with syntax highlighting (CodeMirror)
- Intercept rules, block lists, request/response mapping, network simulation
- Android MITM: patches APKs to trust the proxy's root CA (`network_security_config.xml` injection), optionally over adb
- Auto-updater (GitHub releases)

## Install

Grab the latest build for your platform from the [Releases page](https://github.com/WarFiN123/packetsniffer/releases/latest) (`.msi` for Windows, `.dmg` for macOS, `.deb`/`.AppImage` for Linux).

## Development

Requires [Bun](https://bun.sh) and the [Tauri](https://v2.tauri.app/start/prerequisites/) toolchain (Rust + platform build deps).

```
bun dev           # Full dev build (Tauri + Vite hot-reload)
bun run build     # Production binary
bun run vite:dev  # Frontend only, no Tauri shell
```

Rust backend only: `cd src-tauri && cargo build` / `cargo check`.

Android APK patching additionally requires `java`/`keytool`, `apktool`, `zipalign`, `apksigner`, and `adb` on `PATH`.

## Contributing

PRs welcome.

1. Fork and branch off `master`.
2. Keep frontend/backend IPC shapes in sync — `HttpSession` and `InterceptConfig` are duplicated between Rust (serde) and TypeScript; a field rename on one side breaks the other silently.
3. No test suite or linter is wired up yet; run `cargo check` and `bun run vite:build` before opening a PR.
4. Open a PR against `master` with a clear description of the change and why.
