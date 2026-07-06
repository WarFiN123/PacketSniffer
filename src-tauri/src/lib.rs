mod apk;
mod cert_store;
mod proxy;
mod system_proxy;

use proxy::engine::ProxyEngine;
use proxy::http::HttpSession;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};
use tauri::{AppHandle, Emitter, Manager, RunEvent};
use tokio::sync::{watch, Mutex};

/// Maximum number of full sessions (with bodies) retained server-side. Older
/// sessions are evicted to bound memory during very long capture runs. The
/// frontend caps its own metadata map to the same value so a row that is still
/// visible can always have its bodies fetched back.
pub const MAX_SESSIONS: usize = 5000;

/// Server-side authoritative store of full sessions (including bodies). The
/// live event stream only carries slim metadata; bodies are fetched from here
/// on demand via `get_session`, and the whole set is dumped via
/// `export_all_sessions`. Bounded to `MAX_SESSIONS` with oldest-first eviction.
#[derive(Default)]
struct SessionStore {
    map: HashMap<u64, HttpSession>,
    order: VecDeque<u64>,
}

impl SessionStore {
    fn insert(&mut self, session: HttpSession) {
        let id = session.id;
        if self.map.insert(id, session).is_none() {
            self.order.push_back(id);
            while self.order.len() > MAX_SESSIONS {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    fn get(&self, id: u64) -> Option<HttpSession> {
        self.map.get(&id).cloned()
    }

    fn all(&self) -> Vec<HttpSession> {
        self.order
            .iter()
            .filter_map(|id| self.map.get(id).cloned())
            .collect()
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

/// Session data sent to the frontend via Tauri events.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub session: proxy::http::HttpSession,
}

/// WebSocket message event sent to the frontend.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WsMessageEvent {
    pub message: proxy::ws::WsMessage,
}

/// Shared proxy state accessible from Tauri commands.
struct ProxyState {
    engine: Arc<Mutex<Option<ProxyEngine>>>,
    sessions: Arc<StdMutex<SessionStore>>,
    /// Per-device USB capture listeners: serial → (loopback port, stop handle).
    device_captures: Arc<StdMutex<HashMap<String, (u16, watch::Sender<bool>)>>>,
}

/// Build the proxy engine's session callback: store the full session (with
/// bodies) server-side, then emit a slim copy (bodies stripped) to the UI. This
/// keeps the high-frequency event stream small while preserving on-demand
/// access to bodies via `get_session`.
fn make_session_callback(
    app: AppHandle,
    store: Arc<StdMutex<SessionStore>>,
) -> impl Fn(&str, HttpSession) + Send + Sync + 'static {
    move |event_type, session| {
        let slim = session.metadata_clone();
        if let Ok(mut store) = store.lock() {
            store.insert(session);
        }
        let event = SessionEvent {
            event_type: event_type.to_string(),
            session: slim,
        };
        let _ = app.emit("proxy-session", &event);
    }
}

// ─── Tauri Commands ──────────────────────────────────────────────────────────

#[tauri::command]
async fn get_proxy_status(state: tauri::State<'_, ProxyState>) -> Result<String, String> {
    let engine = state.engine.lock().await;
    match &*engine {
        Some(e) => Ok(format!("running on port {}", e.port())),
        None => Ok("stopped".to_string()),
    }
}

/// Fetch a full session (including request/response bodies) by id. Bodies are
/// stripped from the live event stream, so the UI calls this when a row is
/// inspected. Returns `None` if the session was evicted or never existed.
#[tauri::command]
fn get_session(id: u64, state: tauri::State<'_, ProxyState>) -> Option<HttpSession> {
    state.sessions.lock().ok().and_then(|s| s.get(id))
}

/// Dump every retained session (with bodies) in capture order — used by the
/// "export session" action, which needs the full bodies the live UI lacks.
#[tauri::command]
fn export_all_sessions(state: tauri::State<'_, ProxyState>) -> Vec<HttpSession> {
    state.sessions.lock().map(|s| s.all()).unwrap_or_default()
}

/// Drop all retained sessions/bodies. Mirrors the UI "clear" action so the
/// server-side store doesn't keep bodies for rows the user already cleared.
#[tauri::command]
fn clear_sessions(state: tauri::State<'_, ProxyState>) {
    if let Ok(mut s) = state.sessions.lock() {
        s.clear();
    }
}

/// Read the current interception rules (No-Cache, block/allow, map, throttle).
#[tauri::command]
fn get_intercept_config() -> proxy::intercept::InterceptConfig {
    proxy::intercept::get()
}

/// Replace the interception rules. Applied to all subsequent proxied requests.
#[tauri::command]
fn set_intercept_config(config: proxy::intercept::InterceptConfig) {
    proxy::intercept::set(config);
}

#[tauri::command]
async fn start_proxy(app: AppHandle, state: tauri::State<'_, ProxyState>) -> Result<u16, String> {
    let mut engine_guard = state.engine.lock().await;
    if engine_guard.is_some() {
        return Err("Proxy is already running".to_string());
    }

    let app_handle_ws = app.clone();
    let store = state.sessions.clone();

    let mut engine = ProxyEngine::new(
        make_session_callback(app.clone(), store),
        move |msg| {
            let event = WsMessageEvent { message: msg };
            let _ = app_handle_ws.emit("ws-message", &event);
        },
    );

    let port = engine.start(8080).await.map_err(|e| e.to_string())?;
    *engine_guard = Some(engine);

    // Set system-wide proxy
    system_proxy::enable(port).map_err(|e| e.to_string())?;

    Ok(port)
}

#[tauri::command]
async fn stop_proxy(state: tauri::State<'_, ProxyState>) -> Result<(), String> {
    // Tear down any device captures first so phones don't get stranded behind a
    // dead proxy (clears their proxy + removes the reverse tunnel).
    let caps: Vec<(String, (u16, watch::Sender<bool>))> =
        state.device_captures.lock().unwrap().drain().collect();
    for (serial, (port, stop_tx)) in caps {
        let _ = stop_tx.send(true);
        let _ = tokio::task::spawn_blocking(move || apk::device_reverse_teardown(&serial, port)).await;
    }

    let mut engine_guard = state.engine.lock().await;
    if let Some(engine) = engine_guard.take() {
        engine.stop().await;
    }
    // Always attempt to disable the system proxy when stopping
    system_proxy::disable().map_err(|e| e.to_string())?;
    Ok(())
}

/// Start capturing a USB-connected device's traffic: spin up a loopback listener
/// tagged with `tag`, tunnel the phone to it via `adb reverse`, and point the
/// phone's proxy at it. Returns the loopback port in use.
#[tauri::command]
async fn start_device_capture(
    serial: String,
    tag: String,
    state: tauri::State<'_, ProxyState>,
) -> Result<u16, String> {
    // Replace any prior capture for this device.
    let prev = state.device_captures.lock().unwrap().remove(&serial);
    if let Some((pport, ptx)) = prev {
        let _ = ptx.send(true);
        let s = serial.clone();
        let _ = tokio::task::spawn_blocking(move || apk::device_reverse_teardown(&s, pport)).await;
    }

    let (port, stop_tx) = {
        let guard = state.engine.lock().await;
        let engine = guard.as_ref().ok_or("Proxy is not running")?;
        engine
            .start_tagged(Arc::from(tag.as_str()))
            .await
            .map_err(|e| e.to_string())?
    };

    let s2 = serial.clone();
    let s3 = serial.clone();
    let setup = tokio::task::spawn_blocking(move || apk::device_reverse_setup(&s2, port))
        .await
        .map_err(|e| format!("task join error: {e}"))?;

    match setup {
        Ok(()) => {
            state
                .device_captures
                .lock()
                .unwrap()
                .insert(serial, (port, stop_tx));
            Ok(port)
        }
        Err(e) => {
            // Teardown any partial reverse setup before stopping the listener
            let _ = tokio::task::spawn_blocking(move || apk::device_reverse_teardown(&s3, port)).await;
            let _ = stop_tx.send(true);
            Err(e)
        }
    }
}

/// Stop a device capture: restore the phone's direct internet and shut the
/// dedicated listener down.
#[tauri::command]
async fn stop_device_capture(
    serial: String,
    state: tauri::State<'_, ProxyState>,
) -> Result<(), String> {
    let entry = state.device_captures.lock().unwrap().remove(&serial);
    if let Some((port, stop_tx)) = entry {
        let _ = stop_tx.send(true);
        let _ = tokio::task::spawn_blocking(move || apk::device_reverse_teardown(&serial, port)).await;
    }
    Ok(())
}

#[tauri::command]
async fn fix_proxy(state: tauri::State<'_, ProxyState>) -> Result<(), String> {
    let engine_guard = state.engine.lock().await;
    if let Some(engine) = &*engine_guard {
        let port = engine.port();
        system_proxy::enable(port).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn set_proxy_port(
    port: u16,
    app: AppHandle,
    state: tauri::State<'_, ProxyState>,
) -> Result<u16, String> {
    let mut engine_guard = state.engine.lock().await;

    if let Some(engine) = engine_guard.take() {
        engine.stop().await;
        let _ = system_proxy::disable();
    }

    let app_handle_ws = app.clone();
    let store = state.sessions.clone();

    let mut engine = ProxyEngine::new(
        make_session_callback(app.clone(), store),
        move |msg| {
            let event = WsMessageEvent { message: msg };
            let _ = app_handle_ws.emit("ws-message", &event);
        },
    );

    let actual_port = engine.start(port).await.map_err(|e| e.to_string())?;
    *engine_guard = Some(engine);

    system_proxy::enable(actual_port).map_err(|e| e.to_string())?;

    Ok(actual_port)
}

#[tauri::command]
async fn install_ca_certificate() -> Result<String, String> {
    cert_store::ensure_ca_trusted()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn open_in_postman() -> Result<(), String> {
    // Postman v12 has no supported deep link that ingests raw collection JSON:
    // local file paths and arbitrary URLs are both rejected ("collection doesn't
    // exist anymore"), and `import/link` only resolves *Postman-hosted* share
    // links. The reliable, version-proof path is to place an equivalent cURL
    // command on the clipboard (done in the frontend) and just bring Postman to
    // the front so the user can paste it into a request URL bar, which Postman
    // expands into a full request.
    open::that("postman://app").map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn check_ca_trusted() -> Result<bool, String> {
    cert_store::check_ca_trusted()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn check_missing_deps() -> Vec<String> {
    cert_store::check_missing_dependencies()
}

#[tauri::command]
async fn install_dependency(package: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        // Only allow packages that the dependency checker itself identified as missing,
        // preventing arbitrary root-level package installation from the frontend.
        let allowed = cert_store::check_missing_dependencies();
        if !allowed.contains(&package) {
            return Err(format!(
                "Package '{}' is not in the allowed install list",
                package
            ));
        }
        cert_store::install_package(&package).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Failed to execute package installation task: {e}"))?
}

// ─── App Entry ───────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Install the ring crypto provider for rustls 0.23+
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    // ── Re-add adb installed in a past session to PATH ───────────────────
    // The "Install adb" step downloads platform-tools into the app data dir and
    // only mutates the live process PATH; on relaunch we must re-register it.
    apk::register_bundled_tools();

    // ── Safety net: clean up stale proxy from a previous crash ───────────
    // If the app was killed without cleanup, the system proxy still points
    // to 127.0.0.1:8080. Detect this and disable it before we start.
    cleanup_stale_proxy();

    // ── Install OS-level signal handler for Ctrl+C / process termination ─
    install_ctrl_handler();

    // ── Panic hook: restore proxy on panic ───────────────────────────────
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log::error!("PANIC — restoring system proxy");
        let _ = system_proxy::disable();
        default_panic(info);
    }));

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(ProxyState {
            engine: Arc::new(Mutex::new(None)),
            sessions: Arc::new(StdMutex::new(SessionStore::default())),
            device_captures: Arc::new(StdMutex::new(HashMap::new())),
        })
        .invoke_handler(tauri::generate_handler![
            get_proxy_status,
            get_session,
            export_all_sessions,
            clear_sessions,
            get_intercept_config,
            set_intercept_config,
            start_proxy,
            stop_proxy,
            start_device_capture,
            stop_device_capture,
            fix_proxy,
            set_proxy_port,
            install_ca_certificate,
            check_ca_trusted,
            check_missing_deps,
            install_dependency,
            open_in_postman,
            apk::check_apk_tools,
            apk::apk_work_info,
            apk::clear_apk_work,
            apk::cancel_patch,
            apk::list_adb_devices,
            apk::list_device_packages,
            apk::check_app_protection,
            apk::pull_apk,
            apk::patch_apk,
            apk::install_patched_apk,
            apk::replace_patched_apk,
            apk::get_proxy_endpoints,
            apk::install_android_tools,
            apk::install_patch_tools,
            apk::set_device_proxy,
            apk::clear_device_proxy,
            apk::get_device_ip,
            apk::launch_package,
        ])
        .setup(|app| {
            let handle = app.handle().clone();

            // Auto-start the proxy when the app launches
            tauri::async_runtime::spawn(async move {
                let state = handle.state::<ProxyState>();
                let mut engine_guard = state.engine.lock().await;

                // Check (non-privileged) whether the CA is already trusted.
                // Actual installation is driven by the UI after user consent
                // to avoid unexpected UAC/pkexec prompts at startup.
                match cert_store::check_ca_trusted().await {
                    Ok(true) => {
                        log::info!("CA certificate is trusted");
                    }
                    Ok(false) => {
                        log::warn!(
                            "CA certificate is not trusted — the app will prompt for installation"
                        );
                    }
                    Err(e) => {
                        log::warn!("Could not check CA trust status: {}", e);
                    }
                }

                let app_handle_ws = handle.clone();
                let store = state.sessions.clone();
                let mut engine = ProxyEngine::new(
                    make_session_callback(handle.clone(), store),
                    move |msg| {
                        let event = WsMessageEvent { message: msg };
                        let _ = app_handle_ws.emit("ws-message", &event);
                    },
                );

                match engine.start(8080).await {
                    Ok(port) => {
                        log::info!("Proxy auto-started on port {}", port);
                        *engine_guard = Some(engine);

                        match system_proxy::enable(port) {
                            Ok(()) => {
                                log::info!("System proxy set to 127.0.0.1:{}", port);
                            }
                            Err(e) => {
                                log::error!("Failed to set system proxy: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to auto-start proxy: {}", e);
                    }
                }
            });

            // Proxy override monitor task
            let monitor_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
                let mut was_overridden = false;
                loop {
                    interval.tick().await;
                    let state = monitor_handle.state::<ProxyState>();
                    let engine_guard = state.engine.lock().await;
                    if let Some(engine) = &*engine_guard {
                        let expected_port = engine.port();
                        let is_overridden = system_proxy::is_overridden(expected_port);

                        if is_overridden != was_overridden {
                            was_overridden = is_overridden;

                            #[derive(Serialize, Clone)]
                            struct ProxyOverrideEvent {
                                overridden: bool,
                            }

                            let _ = monitor_handle.emit(
                                "proxy_overridden",
                                ProxyOverrideEvent {
                                    overridden: is_overridden,
                                },
                            );
                        }
                    } else {
                        // If proxy is stopped, it shouldn't show as overridden.
                        if was_overridden {
                            was_overridden = false;

                            #[derive(Serialize, Clone)]
                            struct ProxyOverrideEvent {
                                overridden: bool,
                            }

                            let _ = monitor_handle
                                .emit("proxy_overridden", ProxyOverrideEvent { overridden: false });
                        }
                    }
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    // Use run_return-style callback to handle RunEvent::Exit reliably.
    // This fires even when the app is closed via Ctrl+C from the dev server,
    // window X button, or any other exit path.
    app.run(|app_handle, event| {
        match event {
            RunEvent::ExitRequested { .. } => {
                // Don't prevent exit — cleanup runs in RunEvent::Exit.
            }
            RunEvent::Exit => {
                log::info!("RunEvent::Exit — cleaning up device captures and restoring system proxy");

                // Drain device captures to avoid stranding phones behind a dead proxy
                if let Some(state) = app_handle.try_state::<ProxyState>() {
                    let caps: Vec<(String, (u16, watch::Sender<bool>))> =
                        state.device_captures.lock().unwrap().drain().collect();
                    for (serial, (port, stop_tx)) in caps {
                        let _ = stop_tx.send(true);
                        apk::device_reverse_teardown(&serial, port);
                    }
                }

                if let Err(e) = system_proxy::disable() {
                    log::error!("Failed to restore proxy on exit: {}", e);
                } else {
                    log::info!("System proxy restored successfully on exit");
                }
            }
            _ => {}
        }
    });
}

// ─── Stale proxy cleanup ─────────────────────────────────────────────────────
// If the app crashed or was killed previously, the system proxy may still point
// to our address. Check at startup and clean up if so.

fn cleanup_stale_proxy() {
    #[cfg(target_os = "windows")]
    {
        let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        let enabled = system_proxy::reg_query_dword(reg_path, "ProxyEnable").unwrap_or(0);
        let server = system_proxy::reg_query_string(reg_path, "ProxyServer").unwrap_or_default();

        if enabled == 1 && server.starts_with("127.0.0.1:") {
            log::warn!(
                "Detected stale proxy from previous crash: {} — disabling",
                server
            );

            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;

            let _ = std::process::Command::new("reg")
                .args([
                    "add",
                    reg_path,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output();

            // Also clean up the ProxyServer value so it doesn't get saved as the "original" state
            let _ = std::process::Command::new("reg")
                .args(["delete", reg_path, "/v", "ProxyServer", "/f"])
                .creation_flags(CREATE_NO_WINDOW)
                .output();

            system_proxy::notify_proxy_change();
            log::info!("Cleaned up stale proxy from previous session");
        }

        // Also clean up stale environment variable proxy settings from a previous crash
        let env_path = r"HKCU\Environment";
        let proxy_keys = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"];
        let has_stale_proxy = proxy_keys.iter().any(|key| {
            system_proxy::reg_query_string(env_path, key)
                .map(|v| v.starts_with("http://127.0.0.1:"))
                .unwrap_or(false)
        });

        if has_stale_proxy {
            log::warn!("Detected stale proxy environment variables — clearing");
            // Delegate to disable which clears env vars
            let _ = system_proxy::disable();
        }
    }
}

// ─── Console Ctrl Handler (Windows) ──────────────────────────────────────────

fn install_ctrl_handler() {
    #[cfg(target_os = "windows")]
    {
        unsafe {
            #[link(name = "kernel32")]
            extern "system" {
                fn SetConsoleCtrlHandler(
                    handler: Option<unsafe extern "system" fn(u32) -> i32>,
                    add: i32,
                ) -> i32;
            }

            unsafe extern "system" fn handler(ctrl_type: u32) -> i32 {
                log::info!("Console ctrl event {} — restoring system proxy", ctrl_type);
                let _ = system_proxy::disable();
                0
            }

            SetConsoleCtrlHandler(Some(handler), 1);
        }
        log::debug!("Console ctrl handler installed");
    }
}
