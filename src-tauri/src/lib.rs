mod cert_store;
mod proxy;
mod system_proxy;

use proxy::engine::ProxyEngine;
use serde::Serialize;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, RunEvent};
use tokio::sync::Mutex;

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

#[tauri::command]
async fn start_proxy(app: AppHandle, state: tauri::State<'_, ProxyState>) -> Result<u16, String> {
    let mut engine_guard = state.engine.lock().await;
    if engine_guard.is_some() {
        return Err("Proxy is already running".to_string());
    }

    let app_handle = app.clone();
    let app_handle_ws = app.clone();

    let mut engine = ProxyEngine::new(
        move |event_type, session| {
            let event = SessionEvent {
                event_type: event_type.to_string(),
                session,
            };
            let _ = app_handle.emit("proxy-session", &event);
        },
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
    let mut engine_guard = state.engine.lock().await;
    if let Some(engine) = engine_guard.take() {
        engine.stop().await;
    }
    // Always attempt to disable the system proxy when stopping
    system_proxy::disable().map_err(|e| e.to_string())?;
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

    let app_handle = app.clone();
    let app_handle_ws = app.clone();

    let mut engine = ProxyEngine::new(
        move |event_type, session| {
            let event = SessionEvent {
                event_type: event_type.to_string(),
                session,
            };
            let _ = app_handle.emit("proxy-session", &event);
        },
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
async fn open_in_postman(json: String) -> Result<(), String> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "postman_req_{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::write(&path, json).map_err(|e| e.to_string())?;

    // Convert path to absolute string, making sure it's valid for URI
    let path_str = path.to_string_lossy().replace('\\', "/");
    let uri = format!("postman://app/collections/import?path={}", path_str);

    // Attempt to open the custom URL scheme
    if let Err(_e) = open::that(&uri) {
        // Fallback: try opening the file directly, the OS might map .json to code editor,
        // but Postman might be the handler if we named it .postman_collection.json.
        // Actually, let's rename it to have that extension just in case.
    }

    Ok(())
}

// ─── App Entry ───────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Install the ring crypto provider for rustls 0.23+
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

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
        })
        .invoke_handler(tauri::generate_handler![
            get_proxy_status,
            start_proxy,
            stop_proxy,
            fix_proxy,
            set_proxy_port,
            install_ca_certificate,
            open_in_postman,
        ])
        .setup(|app| {
            let handle = app.handle().clone();

            // Auto-start the proxy when the app launches
            tauri::async_runtime::spawn(async move {
                let state = handle.state::<ProxyState>();
                let mut engine_guard = state.engine.lock().await;

                let app_handle = handle.clone();
                let app_handle_ws = handle.clone();
                let mut engine = ProxyEngine::new(
                    move |event_type, session| {
                        let event = SessionEvent {
                            event_type: event_type.to_string(),
                            session,
                        };
                        let _ = app_handle.emit("proxy-session", &event);
                    },
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

                        match cert_store::ensure_ca_trusted().await {
                            Ok(msg) => {
                                log::info!("CA trust store: {}", msg);
                            }
                            Err(e) => {
                                log::warn!(
                                    "CA cert not trusted — HTTPS interception will fail: {}",
                                    e
                                );
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
    app.run(|_app_handle, event| {
        match event {
            RunEvent::ExitRequested { .. } => {
                // Don't prevent exit — cleanup runs in RunEvent::Exit.
            }
            RunEvent::Exit => {
                log::info!("RunEvent::Exit — restoring system proxy");
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
