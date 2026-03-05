// ─── System-Wide Proxy Configuration ──────────────────────────────────────────
// Automatically sets the OS system proxy to route all traffic through our MITM
// proxy, and restores the original settings when the app exits.
//
// Windows: Registry via reg.exe + InternetSetOptionW notification
// macOS:   networksetup -setwebproxy / -setsecurewebproxy
// Linux:   gsettings (GNOME) — best-effort

use std::sync::Mutex;

/// Saved proxy state so we can restore on exit.
static ORIGINAL_STATE: Mutex<Option<OriginalProxyState>> = Mutex::new(None);

#[derive(Debug, Clone)]
struct OriginalProxyState {
    #[cfg(target_os = "windows")]
    proxy_enable: u32,
    #[cfg(target_os = "windows")]
    proxy_server: String,
    /// WinHTTP proxy was previously set (so we restore it instead of resetting)
    #[cfg(target_os = "windows")]
    winhttp_was_set: bool,
    #[cfg(target_os = "windows")]
    winhttp_proxy: String,
    #[cfg(target_os = "windows")]
    winhttp_bypass: String,
    #[cfg(target_os = "macos")]
    services: Vec<String>,
    #[cfg(target_os = "macos")]
    http_enabled: bool,
    #[cfg(target_os = "macos")]
    http_server: String,
    #[cfg(target_os = "macos")]
    http_port: String,
    #[cfg(target_os = "macos")]
    https_enabled: bool,
    #[cfg(target_os = "macos")]
    https_server: String,
    #[cfg(target_os = "macos")]
    https_port: String,
    #[cfg(target_os = "linux")]
    mode: String,
    #[cfg(target_os = "linux")]
    http_host: String,
    #[cfg(target_os = "linux")]
    http_port: u16,
    #[cfg(target_os = "linux")]
    https_host: String,
    #[cfg(target_os = "linux")]
    https_port: u16,
}

/// Enable the system proxy pointing to 127.0.0.1:<port>.
/// Saves the current state for later restoration.
pub fn enable(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "windows")]
    return enable_windows(port);

    #[cfg(target_os = "macos")]
    return enable_macos(port);

    #[cfg(target_os = "linux")]
    return enable_linux(port);

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        log::warn!("System proxy auto-configuration not supported on this platform");
        Ok(())
    }
}

/// Restore the original system proxy settings.
pub fn disable() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "windows")]
    return disable_windows();

    #[cfg(target_os = "macos")]
    return disable_macos();

    #[cfg(target_os = "linux")]
    return disable_linux();

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    Ok(())
}

/// Check if the system proxy has been overridden by another application or user.
pub fn is_overridden(port: u16) -> bool {
    #[cfg(target_os = "windows")]
    return is_overridden_windows(port);

    #[cfg(target_os = "macos")]
    return is_overridden_macos(port);

    #[cfg(target_os = "linux")]
    return is_overridden_linux(port);

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    false
}

// ─── Windows ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn enable_windows(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    // Save current state
    let current_enable = reg_query_dword(reg_path, "ProxyEnable").unwrap_or(0);
    let current_server = reg_query_string(reg_path, "ProxyServer").unwrap_or_default();
    log::debug!(
        "Current proxy state: enable={}, server='{}'",
        current_enable,
        current_server
    );

    let mut state = ORIGINAL_STATE.lock().unwrap();
    // Only save the original state if we haven't already saved it
    if state.is_none() {
        if !(current_enable == 1
            && (current_server.starts_with("127.0.0.1:")
                || current_server.starts_with("localhost:")))
        {
            // Query WinHTTP state before we change it
            let (winhttp_was_set, winhttp_proxy, winhttp_bypass) = winhttp_query();
            *state = Some(OriginalProxyState {
                proxy_enable: current_enable,
                proxy_server: current_server,
                winhttp_was_set,
                winhttp_proxy,
                winhttp_bypass,
            });
        }
    }

    // Set proxy via reg.exe
    let proxy_addr = format!("127.0.0.1:{}", port);

    let output = Command::new("reg")
        .args([
            "add",
            reg_path,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Failed to set ProxyEnable: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let output = Command::new("reg")
        .args([
            "add",
            reg_path,
            "/v",
            "ProxyServer",
            "/t",
            "REG_SZ",
            "/d",
            &proxy_addr,
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Failed to set ProxyServer: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    // Bypass list — don't proxy localhost traffic (avoids loops)
    let bypass = "<local>;localhost;127.0.0.1;::1";
    let output = Command::new("reg")
        .args([
            "add",
            reg_path,
            "/v",
            "ProxyOverride",
            "/t",
            "REG_SZ",
            "/d",
            bypass,
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Failed to set ProxyOverride: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    // Notify the system that proxy settings changed (WinINET)
    notify_windows_proxy_change();

    // Also set WinHTTP proxy for non-browser apps
    let winhttp_bypass = "<local>;localhost;127.0.0.1;::1";
    let _ = winhttp_set_proxy(&proxy_addr, winhttp_bypass);

    log::info!("System proxy set to {}", proxy_addr);
    Ok(())
}

#[cfg(target_os = "windows")]
fn disable_windows() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let state = ORIGINAL_STATE.lock().unwrap().take();
    let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    // If we never enabled the proxy, nothing to restore
    let original = match state {
        Some(s) => s,
        None => {
            log::debug!("System proxy was never enabled or already disabled, checking if we need to force disable");
            let server = reg_query_string(reg_path, "ProxyServer").unwrap_or_default();
            if server.starts_with("127.0.0.1:") {
                let _ = Command::new("reg")
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
                notify_windows_proxy_change();
            }
            return Ok(());
        }
    };

    let enable_str = original.proxy_enable.to_string();
    let _ = Command::new("reg")
        .args([
            "add",
            reg_path,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            &enable_str,
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if original.proxy_server.is_empty() {
        let _ = Command::new("reg")
            .args(["delete", reg_path, "/v", "ProxyServer", "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    } else {
        let _ = Command::new("reg")
            .args([
                "add",
                reg_path,
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                &original.proxy_server,
                "/f",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    notify_windows_proxy_change();

    // Restore WinHTTP proxy
    if original.winhttp_was_set {
        let _ = winhttp_set_proxy(&original.winhttp_proxy, &original.winhttp_bypass);
    } else {
        let _ = winhttp_reset();
    }

    log::info!("System proxy restored to original settings");
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_overridden_windows(port: u16) -> bool {
    let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let enable = reg_query_dword(reg_path, "ProxyEnable").unwrap_or(0);
    let server = reg_query_string(reg_path, "ProxyServer").unwrap_or_default();

    // We expect the proxy to be enabled and pointing to 127.0.0.1:port
    if enable != 1 {
        return true;
    }

    let expected = format!("127.0.0.1:{}", port);
    if server != expected {
        // Strict check: if it's not exactly our string, it might have been modified.
        return true;
    }

    false
}

/// Query a REG_DWORD value from the registry using reg.exe
#[cfg(target_os = "windows")]
pub fn reg_query_dword(key_path: &str, value_name: &str) -> Option<u32> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("reg")
        .args(["query", key_path, "/v", value_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Output format: "    ProxyEnable    REG_DWORD    0x1"
    for line in text.lines() {
        if line.contains(value_name) && line.contains("REG_DWORD") {
            let hex = line.split_whitespace().last()?;
            return u32::from_str_radix(hex.trim_start_matches("0x"), 16).ok();
        }
    }
    None
}

/// Query a REG_SZ value from the registry using reg.exe
#[cfg(target_os = "windows")]
pub fn reg_query_string(key_path: &str, value_name: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("reg")
        .args(["query", key_path, "/v", value_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Output format: "    ProxyServer    REG_SZ    127.0.0.1:8080"
    for line in text.lines() {
        if line.contains(value_name) && line.contains("REG_SZ") {
            // Find the value after "REG_SZ"
            if let Some(idx) = line.find("REG_SZ") {
                let after = &line[idx + 6..];
                return Some(after.trim().to_string());
            }
        }
    }
    None
}

/// Query current WinHTTP proxy settings.
/// Returns (is_set, proxy_server, bypass_list).
#[cfg(target_os = "windows")]
fn winhttp_query() -> (bool, String, String) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = match Command::new("netsh")
        .args(["winhttp", "show", "proxy"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => o,
        Err(_) => return (false, String::new(), String::new()),
    };
    let text = String::from_utf8_lossy(&output.stdout);

    // Output looks like:
    //   Current WinHTTP proxy settings:
    //       Direct access (no proxy server).
    // OR:
    //   Current WinHTTP proxy settings:
    //       Proxy Server(s) :  127.0.0.1:8080
    //       Bypass List     :  <local>;localhost

    if text.contains("Direct access") {
        return (false, String::new(), String::new());
    }

    let mut proxy = String::new();
    let mut bypass = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Proxy Server(s)") {
            proxy = rest.trim().trim_start_matches(':').trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("Bypass List") {
            bypass = rest.trim().trim_start_matches(':').trim().to_string();
        }
    }

    (!proxy.is_empty(), proxy, bypass)
}

/// Set WinHTTP proxy for non-browser apps (PowerShell, Python, native apps, etc.)
#[cfg(target_os = "windows")]
fn winhttp_set_proxy(
    proxy_addr: &str,
    bypass: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("netsh")
        .args([
            "winhttp",
            "set",
            "proxy",
            &format!("proxy-server={}", proxy_addr),
            &format!("bypass-list={}", bypass),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        log::debug!(
            "WinHTTP proxy not set (requires elevation): {} {}",
            stderr.trim(),
            stdout.trim()
        );
    } else {
        log::info!("WinHTTP proxy set to {}", proxy_addr);
    }
    Ok(())
}

/// Reset WinHTTP proxy to direct access.
#[cfg(target_os = "windows")]
fn winhttp_reset() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("netsh")
        .args(["winhttp", "reset", "proxy"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        log::warn!(
            "Failed to reset WinHTTP proxy: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        log::info!("WinHTTP proxy reset to direct access");
    }
    Ok(())
}

/// Call InternetSetOption to notify WinINet that proxy settings changed.
/// Without this, running browsers won't pick up the change until restarted.
#[cfg(target_os = "windows")]
fn notify_windows_proxy_change() {
    // INTERNET_OPTION_SETTINGS_CHANGED = 39
    // INTERNET_OPTION_REFRESH = 37
    unsafe {
        #[link(name = "wininet")]
        extern "system" {
            fn InternetSetOptionW(
                hinternet: *mut std::ffi::c_void,
                dwoption: u32,
                lpbuffer: *mut std::ffi::c_void,
                dwbufferlength: u32,
            ) -> i32;
        }

        InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0);
        InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0);
    }
}

/// Public alias for `notify_windows_proxy_change()` used by `lib.rs`.
#[cfg(target_os = "windows")]
pub fn notify_proxy_change() {
    notify_windows_proxy_change();
}

// ─── macOS ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn get_active_network_services() -> Vec<String> {
    use std::process::Command;

    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .unwrap_or_else(|_| panic!("Failed to list network services"));

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .filter(|line| !line.starts_with('*'))
        .map(|s| s.to_string())
        .collect()
}

#[cfg(target_os = "macos")]
fn enable_macos(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    let services = get_active_network_services();
    let primary = services
        .first()
        .cloned()
        .unwrap_or_else(|| "Wi-Fi".to_string());

    let get_proxy = |service: &str, proto: &str| -> (bool, String, String) {
        let output = Command::new("networksetup")
            .args([&format!("-get{}proxy", proto), service])
            .output()
            .ok();
        if let Some(out) = output {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            let enabled = text.contains("Enabled: Yes");
            let server = text
                .lines()
                .find(|l| l.starts_with("Server:"))
                .map(|l| l.trim_start_matches("Server: ").to_string())
                .unwrap_or_default();
            let port = text
                .lines()
                .find(|l| l.starts_with("Port:"))
                .map(|l| l.trim_start_matches("Port: ").to_string())
                .unwrap_or_default();
            (enabled, server, port)
        } else {
            (false, String::new(), String::new())
        }
    };

    let (http_enabled, http_server, http_port) = get_proxy(&primary, "web");
    let (https_enabled, https_server, https_port) = get_proxy(&primary, "secureweb");

    let mut state = ORIGINAL_STATE.lock().unwrap();
    if state.is_none() {
        let is_us = (http_enabled && (http_server == "127.0.0.1" || http_server == "localhost"))
            || (https_enabled && (https_server == "127.0.0.1" || https_server == "localhost"));
        if !is_us {
            *state = Some(OriginalProxyState {
                services: services.clone(),
                http_enabled,
                http_server,
                http_port,
                https_enabled,
                https_server,
                https_port,
            });
        }
    }

    let port_str = port.to_string();
    for service in &services {
        let _ = Command::new("networksetup")
            .args(["-setwebproxy", service, "127.0.0.1", &port_str])
            .status();
        let _ = Command::new("networksetup")
            .args(["-setsecurewebproxy", service, "127.0.0.1", &port_str])
            .status();
        let _ = Command::new("networksetup")
            .args([
                "-setproxybypassdomains",
                service,
                "localhost",
                "127.0.0.1",
                "::1",
            ])
            .status();
    }

    log::info!(
        "System proxy set to 127.0.0.1:{} on {} services",
        port,
        services.len()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn disable_macos() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    let state = ORIGINAL_STATE.lock().unwrap().take();

    match state {
        Some(original) => {
            for service in &original.services {
                if original.http_enabled {
                    let _ = Command::new("networksetup")
                        .args([
                            "-setwebproxy",
                            service,
                            &original.http_server,
                            &original.http_port,
                        ])
                        .status();
                } else {
                    let _ = Command::new("networksetup")
                        .args(["-setwebproxystate", service, "off"])
                        .status();
                }
                if original.https_enabled {
                    let _ = Command::new("networksetup")
                        .args([
                            "-setsecurewebproxy",
                            service,
                            &original.https_server,
                            &original.https_port,
                        ])
                        .status();
                } else {
                    let _ = Command::new("networksetup")
                        .args(["-setsecurewebproxystate", service, "off"])
                        .status();
                }
            }
        }
        None => {
            // Force disable just in case
            for service in get_active_network_services() {
                let _ = Command::new("networksetup")
                    .args(["-setwebproxystate", &service, "off"])
                    .status();
                let _ = Command::new("networksetup")
                    .args(["-setsecurewebproxystate", &service, "off"])
                    .status();
            }
        }
    }

    log::info!("System proxy restored to original settings");
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_overridden_macos(port: u16) -> bool {
    use std::process::Command;

    let services = get_active_network_services();
    let primary = services.first().map(|s| s.as_str()).unwrap_or("Wi-Fi");

    let output = Command::new("networksetup")
        .args(["-getwebproxy", primary])
        .output()
        .ok();

    if let Some(out) = output {
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let enabled = text.contains("Enabled: Yes");
        let server_line = text.lines().find(|l| l.starts_with("Server:"));
        let port_line = text.lines().find(|l| l.starts_with("Port:"));

        if !enabled {
            return true;
        }

        if let (Some(s), Some(p)) = (server_line, port_line) {
            let s_val = s.trim_start_matches("Server: ").trim();
            let p_val = p.trim_start_matches("Port: ").trim();
            if s_val != "127.0.0.1" || p_val != port.to_string() {
                return true;
            }
        } else {
            return true;
        }

        false
    } else {
        // If we can't get the proxy status, assume it's fine to avoid false positives
        false
    }
}

// ─── Linux (GNOME gsettings) ──────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn enable_linux(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    let mode = gsettings_get("org.gnome.system.proxy", "mode");
    let http_host = gsettings_get("org.gnome.system.proxy.http", "host");
    let http_port: u16 = gsettings_get("org.gnome.system.proxy.http", "port")
        .parse()
        .unwrap_or(0);
    let https_host = gsettings_get("org.gnome.system.proxy.https", "host");
    let https_port: u16 = gsettings_get("org.gnome.system.proxy.https", "port")
        .parse()
        .unwrap_or(0);

    let mut state = ORIGINAL_STATE.lock().unwrap();
    if state.is_none() {
        let is_us = mode == "manual" && (http_host == "127.0.0.1" || http_host == "localhost");
        if !is_us {
            *state = Some(OriginalProxyState {
                mode,
                http_host,
                http_port,
                https_host,
                https_port,
            });
        }
    }

    let port_str = port.to_string();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy", "mode", "'manual'"])
        .status();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "host", "'127.0.0.1'"])
        .status();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "port", &port_str])
        .status();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.https", "host", "'127.0.0.1'"])
        .status();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.https", "port", &port_str])
        .status();
    let _ = Command::new("gsettings")
        .args([
            "set",
            "org.gnome.system.proxy",
            "ignore-hosts",
            "['localhost', '127.0.0.1', '::1']",
        ])
        .status();

    log::info!("System proxy set to 127.0.0.1:{}", port);
    Ok(())
}

#[cfg(target_os = "linux")]
fn disable_linux() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    let state = ORIGINAL_STATE.lock().unwrap().take();

    match state {
        Some(original) => {
            let _ = Command::new("gsettings")
                .args([
                    "set",
                    "org.gnome.system.proxy",
                    "mode",
                    &format!("'{}'", original.mode),
                ])
                .status();
            let _ = Command::new("gsettings")
                .args([
                    "set",
                    "org.gnome.system.proxy.http",
                    "host",
                    &format!("'{}'", original.http_host),
                ])
                .status();
            let _ = Command::new("gsettings")
                .args([
                    "set",
                    "org.gnome.system.proxy.http",
                    "port",
                    &original.http_port.to_string(),
                ])
                .status();
            let _ = Command::new("gsettings")
                .args([
                    "set",
                    "org.gnome.system.proxy.https",
                    "host",
                    &format!("'{}'", original.https_host),
                ])
                .status();
            let _ = Command::new("gsettings")
                .args([
                    "set",
                    "org.gnome.system.proxy.https",
                    "port",
                    &original.https_port.to_string(),
                ])
                .status();
        }
        None => {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "'none'"])
                .status();
        }
    }

    log::info!("System proxy restored to original settings");
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_overridden_linux(port: u16) -> bool {
    let mode = gsettings_get("org.gnome.system.proxy", "mode");
    let http_host = gsettings_get("org.gnome.system.proxy.http", "host");
    let http_port = gsettings_get("org.gnome.system.proxy.http", "port");

    if mode != "manual" {
        return true;
    }

    if http_host != "127.0.0.1" {
        return true;
    }

    if http_port != port.to_string() {
        return true;
    }

    false
}

#[cfg(target_os = "linux")]
fn gsettings_get(schema: &str, key: &str) -> String {
    use std::process::Command;
    Command::new("gsettings")
        .args(["get", schema, key])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .trim_matches('\'')
                .to_string()
        })
        .unwrap_or_default()
}
