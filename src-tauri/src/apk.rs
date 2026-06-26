// ─── APK Patching for Android MITM ───────────────────────────────────────────
// Repackages an Android APK so the proxy can decrypt its HTTPS traffic.
//
// Android 7+ apps ignore user-installed CA certs by default, so a stock app
// won't trust our MITM root CA even after the cert is installed on the phone.
// This module decompiles the APK (apktool), injects a custom
// `network_security_config.xml` that trusts our CA — optionally *embedding* the
// CA as a raw resource so NO phone-side cert install is needed — then rebuilds
// and re-signs it (zipalign + apksigner). The APK can be sourced from a local
// file (drag & drop) or pulled off a USB-connected device via adb.
//
// Intended for authorized malware analysis only. Config-based cert pinning is
// removed (we overwrite the security config), but code-level / native pinning
// survives — that requires Frida and is reported as a warning.
//
// Toolchain (must be on PATH): java/keytool, apktool, zipalign, apksigner, adb.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tauri::{AppHandle, Emitter};

// ─── Data shapes (serde camelCase — mirror these on the frontend) ─────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdbDevice {
    pub serial: String,
    pub state: String, // "device", "offline", "unauthorized", ...
    pub model: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePackage {
    pub package: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchOpts {
    /// Absolute path to the source .apk (local file or previously pulled).
    pub apk_path: String,
    /// Bake the proxy's `ca-cert.pem` into the APK as a trust anchor. When true
    /// the patched app trusts the proxy with no cert install on the device.
    pub embed_proxy_ca: bool,
    /// Also trust user-installed CAs (the device's user cert store).
    pub trust_user_store: bool,
    /// Set `android:debuggable="true"` (useful for Frida / runtime hooking).
    pub make_debuggable: bool,
    /// Inject a Frida gadget so a non-rooted device can hook the app at runtime
    /// (defeats code-level cert pinning). Requires `frida_gadget_path`.
    pub inject_frida: bool,
    /// Path to a `libfrida-gadget.so` matching the target device's ABI. Frida
    /// gadgets are version- and arch-specific, so the user supplies the binary.
    #[serde(default)]
    pub frida_gadget_path: String,
    /// Target ABI dir for the gadget (e.g. "arm64-v8a"). "auto" picks the best
    /// ABI already present in the APK.
    #[serde(default)]
    pub frida_abi: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchResult {
    pub output_path: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PatchProgress {
    stage: String,
    message: String,
}

// ─── Tauri commands ───────────────────────────────────────────────────────────

/// Names of required external tools that are NOT found on PATH.
#[tauri::command]
pub fn check_apk_tools() -> Vec<String> {
    // Refresh PATH (registry + bundled adb) first, so a tool installed since the
    // app launched — or in a past session — is visible without a restart.
    register_bundled_tools();
    ["java", "keytool", "apktool", "zipalign", "apksigner", "adb"]
        .into_iter()
        .filter(|bin| !tool_on_path(bin))
        .map(|bin| bin.to_string())
        .collect()
}

/// Whether a tool resolves on PATH. Uses `where` (Windows) / `which` (unix) so
/// batch-wrapper tools are found — on Windows apktool & apksigner are `.bat`/
/// `.cmd`, which `Command::new` (it only appends `.exe`) would miss.
fn tool_on_path(bin: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        Command::new("where")
            .arg(bin)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("which")
            .arg(bin)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// List adb-visible devices (`adb devices -l`).
#[tauri::command]
pub async fn list_adb_devices() -> Result<Vec<AdbDevice>, String> {
    tokio::task::spawn_blocking(adb_devices)
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

/// List third-party (sideloaded) packages on a device — the relevant set for
/// malware analysis. System packages are excluded.
#[tauri::command]
pub async fn list_device_packages(serial: String) -> Result<Vec<DevicePackage>, String> {
    validate_serial(&serial)?;
    tokio::task::spawn_blocking(move || device_packages(&serial))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

/// Pull a package's base APK off a device into the working directory and return
/// the local path. Split APKs are not merged — only base.apk is pulled.
#[tauri::command]
pub async fn pull_apk(serial: String, package: String) -> Result<String, String> {
    validate_serial(&serial)?;
    validate_package(&package)?;
    tokio::task::spawn_blocking(move || pull_base_apk(&serial, &package))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

/// Decompile → inject network-security-config → rebuild → align → sign.
/// Emits `apk-patch-progress` events throughout. Returns the signed APK path.
#[tauri::command]
pub async fn patch_apk(app: AppHandle, opts: PatchOpts) -> Result<PatchResult, String> {
    tokio::task::spawn_blocking(move || run_patch(&app, opts))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

/// Install (or reinstall) a patched APK on a device. `-r` keeps data, `-t`
/// allows test/debuggable packages.
#[tauri::command]
pub async fn install_patched_apk(
    serial: String,
    apk_path: String,
    package: Option<String>,
) -> Result<String, String> {
    validate_serial(&serial)?;
    let apk = validate_apk_path(&apk_path)?;
    if let Some(p) = &package {
        validate_package(p)?;
    }
    tokio::task::spawn_blocking(move || {
        let first = run(
            Command::new("adb")
                .args(["-s", &serial, "install", "-r", "-t"])
                .arg(&apk),
            "adb install",
        );
        match first {
            Ok(_) => Ok("Installed".to_string()),
            Err(e) => {
                // The patched APK is re-signed with our debug key, so it can't
                // update a store-signed install — Android rejects the signature
                // mismatch. Return an error requiring confirmation rather than
                // automatically deleting data.
                let sig_conflict = e.contains("signatures do not match")
                    || e.contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE");
                if sig_conflict && package.is_some() {
                    return Err(format!(
                        "{e}\nThe patched app is signed differently than the one on the phone. \
                         Installing it requires uninstalling the original app, which will erase its data. \
                         Uninstall the app manually, then retry."
                    ));
                }
                if sig_conflict && package.is_none() {
                    return Err(format!(
                        "{e}\nThe patched app is signed differently than the one on the phone — \
                         uninstall the original app, then retry."
                    ));
                }
                Err(e)
            }
        }
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

// ─── Android device onboarding (guided "Add Device" walkthrough) ──────────────
// These power the in-app walkthrough that connects a phone, routes its Wi-Fi
// traffic through the desktop proxy and surfaces it in the inspector — no manual
// adb/curl steps for the user. Patching (above) stays available as the advanced
// path for apps that pin certs or ignore user CAs.

/// Desktop proxy endpoint a phone can be pointed at. The proxy binds
/// `0.0.0.0:<port>`, so any device on the same network can reach it via the
/// host's LAN IP. We surface the most likely route IP plus the literal port.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyEndpoints {
    /// Best-guess LAN IP a phone on the same Wi-Fi can reach (e.g. 192.168.1.20).
    pub lan_ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolsProgress {
    stage: String,
    message: String,
}

/// LAN IP the desktop proxy is reachable on, for pointing a phone at it.
#[tauri::command]
pub fn get_proxy_endpoints(port: u16) -> ProxyEndpoints {
    ProxyEndpoints {
        lan_ip: primary_lan_ip().unwrap_or_else(|| "127.0.0.1".to_string()),
        port,
    }
}

/// Download Google's `platform-tools` (which contains `adb`) into the app data
/// dir and prepend it to this process's PATH so `adb` resolves immediately —
/// the one tool needed to connect a phone and watch its traffic. Emits
/// `android-tools-progress` events. apktool/zipalign/apksigner/java are only
/// needed for the advanced *patch* path and are not fetched here.
#[tauri::command]
pub async fn install_android_tools(app: AppHandle) -> Result<String, String> {
    tokio::task::spawn_blocking(move || download_platform_tools(&app))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

/// Best-effort install of the optional *patch* toolchain (apktool, zipalign,
/// apksigner, keytool/java) via the OS package manager. Returns a summary of
/// what was installed and what still needs manual setup. Emits
/// `android-tools-progress`.
#[tauri::command]
pub async fn install_patch_tools(app: AppHandle) -> Result<String, String> {
    tokio::task::spawn_blocking(move || install_patch_tools_impl(&app))
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

fn install_patch_tools_impl(app: &AppHandle) -> Result<String, String> {
    let missing: Vec<String> = check_apk_tools()
        .into_iter()
        .filter(|t| t != "adb")
        .collect();
    if missing.is_empty() {
        return Ok("All patch tools are already installed.".to_string());
    }
    platform_install_patch(app, &missing)
}

#[cfg(target_os = "linux")]
fn platform_install_patch(app: &AppHandle, missing: &[String]) -> Result<String, String> {
    let mut pkgs: Vec<&str> = Vec::new();
    for t in missing {
        match t.as_str() {
            "java" | "keytool" => pkgs.push("default-jdk"),
            "apktool" => pkgs.push("apktool"),
            "zipalign" => pkgs.push("zipalign"),
            "apksigner" => pkgs.push("apksigner"),
            _ => {}
        }
    }
    pkgs.sort();
    pkgs.dedup();
    if pkgs.is_empty() {
        return Err("Nothing to install.".to_string());
    }
    let managers: &[(&str, &[&str])] = &[
        ("apt-get", &["install", "-y"]),
        ("dnf", &["install", "-y"]),
        ("pacman", &["-S", "--noconfirm"]),
    ];
    let (mgr, base) = managers
        .iter()
        .find(|(m, _)| {
            Command::new("which").arg(m).output().map(|o| o.status.success()).unwrap_or(false)
        })
        .ok_or("No supported package manager (apt-get, dnf or pacman).")?;
    tools_progress(app, "install", &format!("Installing {} via {mgr}…", pkgs.join(", ")));
    let status = Command::new("pkexec")
        .arg(mgr)
        .args(*base)
        .args(&pkgs)
        .status()
        .map_err(|e| format!("pkexec {mgr}: {e}"))?;
    if !status.success() {
        return Err(format!("{mgr} install failed (exit {status})."));
    }
    tools_progress(app, "done", "Patch tools installed.");
    Ok(format!("Installed: {}.", pkgs.join(", ")))
}

#[cfg(target_os = "macos")]
fn platform_install_patch(app: &AppHandle, missing: &[String]) -> Result<String, String> {
    if Command::new("brew").arg("--version").output().is_err() {
        return Err("Homebrew not found — install it from brew.sh, then retry.".to_string());
    }
    let mut formulae: Vec<&str> = Vec::new();
    let mut build_tools = false;
    for t in missing {
        match t.as_str() {
            "java" | "keytool" => formulae.push("openjdk"),
            "apktool" => formulae.push("apktool"),
            "zipalign" | "apksigner" => build_tools = true,
            _ => {}
        }
    }
    formulae.sort();
    formulae.dedup();
    if !formulae.is_empty() {
        tools_progress(app, "install", &format!("brew install {}…", formulae.join(" ")));
        let status = Command::new("brew")
            .arg("install")
            .args(&formulae)
            .status()
            .map_err(|e| format!("brew: {e}"))?;
        if !status.success() {
            return Err("brew install failed.".to_string());
        }
    }
    tools_progress(app, "done", "Done.");
    let mut msg = if formulae.is_empty() {
        String::new()
    } else {
        format!("Installed {}. ", formulae.join(", "))
    };
    if build_tools {
        msg.push_str(
            "zipalign & apksigner ship in the Android SDK build-tools — install via \
             Android Studio ▸ SDK Manager, then reopen this window.",
        );
    }
    Ok(msg)
}

#[cfg(target_os = "windows")]
fn platform_install_patch(app: &AppHandle, missing: &[String]) -> Result<String, String> {
    let mut done: Vec<&str> = Vec::new();
    let mut manual: Vec<&str> = Vec::new();
    let has_winget = Command::new("winget").arg("--version").output().is_ok();

    if missing.iter().any(|t| t == "java" || t == "keytool") {
        if has_winget {
            tools_progress(app, "install", "Installing OpenJDK via winget…");
            // Pin `--source winget`: a broken msstore source otherwise makes
            // winget bail with "specify one of them using --source".
            let _ = Command::new("winget")
                .args([
                    "install", "-e", "--id", "Microsoft.OpenJDK.17",
                    "--source", "winget", "--silent",
                    "--accept-source-agreements", "--accept-package-agreements",
                ])
                .status();
            // The installer updates machine PATH, but our process won't see it
            // until restart — add the JDK's bin dir to PATH now.
            add_winget_jdk_to_path();
        }
        // Judge by whether java actually resolves, not winget's exit code
        // (it returns non-zero for "already installed" and other benign cases).
        if Command::new("java").arg("-version").output().is_ok() {
            done.push("java/keytool");
        } else {
            manual.push("java");
        }
    }
    if missing.iter().any(|t| t == "apktool") {
        manual.push("apktool");
    }
    if missing.iter().any(|t| t == "zipalign") {
        manual.push("zipalign");
    }
    if missing.iter().any(|t| t == "apksigner") {
        manual.push("apksigner");
    }

    tools_progress(app, "done", "Done.");

    let mut msg = String::new();
    if !done.is_empty() {
        msg.push_str(&format!("Installed {}. ", done.join(", ")));
    }
    if !manual.is_empty() {
        msg.push_str(&format!(
            "Install {} manually: apktool from apktool.org; zipalign & apksigner come with \
             the Android SDK build-tools (Android Studio ▸ SDK Manager). Add them to PATH, \
             then reopen this window.",
            manual.join(", ")
        ));
    }
    if msg.is_empty() {
        msg.push_str("Nothing to install.");
    }
    Ok(msg)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_install_patch(_app: &AppHandle, _missing: &[String]) -> Result<String, String> {
    Err("Automatic patch-tool install isn't supported on this platform.".to_string())
}

/// Point a USB-connected device's global HTTP proxy at `host:port` (the desktop
/// proxy's LAN endpoint). Works on most non-rooted devices via `settings`.
#[tauri::command]
pub async fn set_device_proxy(serial: String, endpoint: String) -> Result<String, String> {
    validate_serial(&serial)?;
    validate_endpoint(&endpoint)?;
    tokio::task::spawn_blocking(move || {
        run(
            Command::new("adb").args([
                "-s", &serial, "shell", "settings", "put", "global", "http_proxy", &endpoint,
            ]),
            "adb set proxy",
        )?;
        Ok(format!("Proxy set to {endpoint}"))
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

/// Clear a device's global HTTP proxy (restores direct traffic). Best-effort —
/// called on disconnect so we don't strand the phone behind a dead proxy.
#[tauri::command]
pub async fn clear_device_proxy(serial: String) -> Result<String, String> {
    validate_serial(&serial)?;
    tokio::task::spawn_blocking(move || {
        run(
            Command::new("adb").args([
                "-s", &serial, "shell", "settings", "put", "global", "http_proxy", ":0",
            ]),
            "adb clear proxy",
        )?;
        Ok("Proxy cleared".to_string())
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

/// Read a device's Wi-Fi IPv4 address — used both to confirm the phone is on a
/// network and to tag/filter its traffic in the inspector by source.
#[tauri::command]
pub async fn get_device_ip(serial: String) -> Result<String, String> {
    validate_serial(&serial)?;
    tokio::task::spawn_blocking(move || {
        // `ip route get <ip>` prints "... src <device-ip> ..." for the route the
        // phone would actually use — the IP its proxied traffic will arrive from.
        if let Ok(out) = run(
            Command::new("adb").args(["-s", &serial, "shell", "ip", "route", "get", "1.1.1.1"]),
            "adb ip route",
        ) {
            if let Some(ip) = parse_after_token(&out, "src") {
                return Ok(ip);
            }
        }
        // Fallback: parse the wlan0 inet address directly.
        let out = run(
            Command::new("adb").args(["-s", &serial, "shell", "ip", "-f", "inet", "addr", "show", "wlan0"]),
            "adb wlan0 addr",
        )?;
        parse_after_token(&out, "inet")
            .map(|cidr| cidr.split('/').next().unwrap_or(&cidr).to_string())
            .ok_or_else(|| "Could not read the phone's Wi-Fi IP — is Wi-Fi on?".to_string())
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

/// Launch an app on the device by package name so its traffic starts flowing.
#[tauri::command]
pub async fn launch_package(serial: String, package: String) -> Result<String, String> {
    validate_serial(&serial)?;
    validate_package(&package)?;
    tokio::task::spawn_blocking(move || {
        run(
            Command::new("adb").args([
                "-s", &serial, "shell", "monkey", "-p", &package,
                "-c", "android.intent.category.LAUNCHER", "1",
            ]),
            "adb launch",
        )
        .map(|_| format!("Launched {package}"))
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

/// Set up USB capture for a device: tunnel its `localhost:<port>` to the
/// desktop proxy over the cable via `adb reverse`, then point the phone's global
/// HTTP proxy at `127.0.0.1:<port>`. Reliable regardless of firewall / Wi-Fi.
pub fn device_reverse_setup(serial: &str, port: u16) -> Result<(), String> {
    validate_serial(serial)?;
    let tcp = format!("tcp:{port}");
    run(
        Command::new("adb").args(["-s", serial, "reverse", tcp.as_str(), tcp.as_str()]),
        "adb reverse",
    )?;
    let ep = format!("127.0.0.1:{port}");
    run(
        Command::new("adb").args([
            "-s", serial, "shell", "settings", "put", "global", "http_proxy", ep.as_str(),
        ]),
        "adb set proxy",
    )?;
    Ok(())
}

/// Best-effort teardown: restore the phone's direct internet (clear proxy) and
/// remove the reverse tunnel. Called on disconnect so we don't strand the phone
/// behind a dead proxy ("limited connection").
pub fn device_reverse_teardown(serial: &str, port: u16) {
    let _ = Command::new("adb")
        .args(["-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0"])
        .output();
    let tcp = format!("tcp:{port}");
    let _ = Command::new("adb")
        .args(["-s", serial, "reverse", "--remove", tcp.as_str()])
        .output();
}

fn download_platform_tools(app: &AppHandle) -> Result<String, String> {
    let (os, expected_sha256) = if cfg!(target_os = "windows") {
        ("windows", "TODO_REPLACE_WITH_VERIFIED_SHA256_WINDOWS")
    } else if cfg!(target_os = "macos") {
        ("darwin", "TODO_REPLACE_WITH_VERIFIED_SHA256_DARWIN")
    } else {
        ("linux", "TODO_REPLACE_WITH_VERIFIED_SHA256_LINUX")
    };
    // Pinned revision instead of "latest" to prevent supply-chain attacks.
    let url = format!("https://dl.google.com/android/repository/platform-tools_r35.0.2-{os}.zip");
    let dir = data_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create data dir: {e}"))?;
    let zip = dir.join("platform-tools.zip");

    tools_progress(app, "download", "Downloading Android platform-tools…");
    let mut curl = Command::new("curl");
    // `--noproxy *` bypasses the app's own MITM proxy (we'd otherwise download
    // through ourselves with an untrusted CA). `--ssl-no-revoke` works around
    // Windows Schannel failing when the revocation server is unreachable.
    curl.args(["-L", "--fail", "--noproxy", "*"]);
    #[cfg(target_os = "windows")]
    curl.arg("--ssl-no-revoke");
    curl.arg("-o").arg(&zip).arg(&url);
    run(&mut curl, "download platform-tools")?;

    // TODO: Verify SHA-256 before extraction. Example:
    // let bytes = std::fs::read(&zip).map_err(|e| format!("read zip: {e}"))?;
    // let hash = sha2::Sha256::digest(&bytes);
    // let hex = format!("{:x}", hash);
    // if hex != expected_sha256 {
    //     return Err(format!("SHA-256 mismatch: expected {}, got {}", expected_sha256, hex));
    // }
    // Requires adding `sha2` crate to Cargo.toml.

    tools_progress(app, "extract", "Extracting…");
    #[cfg(target_os = "windows")]
    run(
        Command::new("powershell").args(["-NoProfile", "-Command"]).arg(format!(
            "Expand-Archive -Force -LiteralPath '{}' -DestinationPath '{}'",
            zip.display(),
            dir.display()
        )),
        "extract platform-tools",
    )?;
    #[cfg(not(target_os = "windows"))]
    run(
        Command::new("unzip").arg("-o").arg(&zip).arg("-d").arg(&dir),
        "extract platform-tools",
    )?;

    let pt = dir.join("platform-tools");
    if !pt.join(adb_bin()).exists() {
        return Err("platform-tools extracted but adb is missing".to_string());
    }
    prepend_path(&pt);
    let _ = std::fs::remove_file(&zip);
    tools_progress(app, "done", "adb is ready.");
    Ok(pt.to_string_lossy().to_string())
}

fn adb_bin() -> &'static str {
    if cfg!(target_os = "windows") { "adb.exe" } else { "adb" }
}

/// Prepend `dir` to this process's PATH so freshly-installed tools resolve
/// without a restart. Idempotent — won't add the same dir twice. Affects only
/// the running app process.
fn prepend_path(dir: &Path) {
    let sep = if cfg!(target_os = "windows") { ";" } else { ":" };
    let dir_s = dir.to_string_lossy().to_string();
    let cur = std::env::var("PATH").unwrap_or_default();
    let present = cur.split(sep).any(|p| {
        if cfg!(target_os = "windows") {
            p.eq_ignore_ascii_case(&dir_s)
        } else {
            p == dir_s
        }
    });
    if present {
        return;
    }
    std::env::set_var("PATH", format!("{dir_s}{sep}{cur}"));
}

/// Re-add previously bundled platform-tools (adb) to PATH. The installer only
/// mutates the live process's PATH, which is gone after a restart — call this on
/// every launch so an adb installed in a past session keeps working.
pub fn register_bundled_tools() {
    // Pull in PATH changes made by installers (winget JDK, a manually-added
    // apktool, …) that the parent shell's stale PATH hides from us.
    refresh_windows_path();
    if let Ok(dir) = data_dir() {
        let pt = dir.join("platform-tools");
        if pt.join(adb_bin()).exists() {
            prepend_path(&pt);
        }
    }
}

/// Merge the live machine + user PATH (from the registry, fully expanded) into
/// this process's PATH — once. A long-lived launcher (e.g. a dev terminal)
/// passes us a PATH snapshot from before tools were installed, so a tool that's
/// genuinely on PATH still reads as "missing" until we refresh.
#[cfg(target_os = "windows")]
fn refresh_windows_path() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[Environment]::ExpandEnvironmentVariables((@([Environment]::GetEnvironmentVariable('Path','Machine'),[Environment]::GetEnvironmentVariable('Path','User')) -join ';'))",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let reg_path = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => return,
    };
    if reg_path.is_empty() {
        return;
    }
    // Merge live registry PATH into the process PATH, de-duplicated (case-
    // insensitive) so repeated refreshes don't grow PATH unbounded.
    let cur = std::env::var("PATH").unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    let mut merged: Vec<String> = Vec::new();
    for part in cur.split(';').chain(reg_path.split(';')) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if seen.insert(p.to_ascii_lowercase()) {
            merged.push(p.to_string());
        }
    }
    std::env::set_var("PATH", merged.join(";"));
}

#[cfg(not(target_os = "windows"))]
fn refresh_windows_path() {}

/// Find a JDK that winget just installed (Microsoft / Adoptium default dirs) and
/// add its `bin` to PATH so `java` + `keytool` resolve without an app restart.
#[cfg(target_os = "windows")]
fn add_winget_jdk_to_path() {
    for base in [
        r"C:\Program Files\Microsoft",
        r"C:\Program Files\Eclipse Adoptium",
        r"C:\Program Files\Java",
    ] {
        let Ok(rd) = std::fs::read_dir(base) else { continue };
        for entry in rd.flatten() {
            let p = entry.path();
            let is_jdk = p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("jdk"))
                    .unwrap_or(false);
            if is_jdk && p.join("bin").join("java.exe").exists() {
                prepend_path(&p.join("bin"));
            }
        }
    }
}

/// Primary LAN IPv4 of this host, found by asking the OS which local address it
/// would use to reach the internet (no packet is actually sent).
fn primary_lan_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) => Some(v4.to_string()),
        _ => None,
    }
}

/// Return the whitespace token immediately following `token` (e.g. the IP after
/// `src` in an `ip route` line).
fn parse_after_token(s: &str, token: &str) -> Option<String> {
    let mut it = s.split_whitespace();
    while let Some(w) = it.next() {
        if w == token {
            return it.next().map(|v| v.to_string());
        }
    }
    None
}

/// Validate a `host:port` proxy endpoint before handing it to adb.
fn validate_endpoint(ep: &str) -> Result<(), String> {
    let (host, port) = ep.rsplit_once(':').ok_or("Endpoint must be host:port")?;
    if host.is_empty()
        || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        || port.parse::<u16>().is_err()
    {
        return Err("Invalid proxy endpoint".to_string());
    }
    Ok(())
}

fn tools_progress(app: &AppHandle, stage: &str, message: &str) {
    let _ = app.emit(
        "android-tools-progress",
        ToolsProgress {
            stage: stage.to_string(),
            message: message.to_string(),
        },
    );
}

// ─── adb helpers ──────────────────────────────────────────────────────────────

fn adb_devices() -> Result<Vec<AdbDevice>, String> {
    let out = run(Command::new("adb").arg("devices").arg("-l"), "adb devices")?;
    let mut devices = Vec::new();
    for line in out.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let serial = match parts.next() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let state = parts.next().unwrap_or("unknown").to_string();
        // model lives in a `model:Pixel_5` token when `-l` is used.
        let model = parts
            .find_map(|tok| tok.strip_prefix("model:"))
            .unwrap_or("")
            .replace('_', " ");
        devices.push(AdbDevice {
            serial,
            state,
            model,
        });
    }
    Ok(devices)
}

fn device_packages(serial: &str) -> Result<Vec<DevicePackage>, String> {
    let out = run(
        Command::new("adb").args(["-s", serial, "shell", "pm", "list", "packages", "-3"]),
        "pm list packages",
    )?;
    let mut pkgs: Vec<DevicePackage> = out
        .lines()
        .filter_map(|l| l.trim().strip_prefix("package:"))
        .map(|p| DevicePackage {
            package: p.trim().to_string(),
        })
        .collect();
    pkgs.sort_by(|a, b| a.package.cmp(&b.package));
    Ok(pkgs)
}

fn pull_base_apk(serial: &str, package: &str) -> Result<String, String> {
    let out = run(
        Command::new("adb").args(["-s", serial, "shell", "pm", "path", package]),
        "pm path",
    )?;
    let remote_paths: Vec<&str> = out
        .lines()
        .filter_map(|l| l.trim().strip_prefix("package:"))
        .map(str::trim)
        .collect();
    if remote_paths.is_empty() {
        return Err(format!("No APK path found for package {package}"));
    }
    // Prefer base.apk; fall back to the first entry (splits are not merged).
    let remote = remote_paths
        .iter()
        .find(|p| p.ends_with("base.apk"))
        .copied()
        .unwrap_or(remote_paths[0]);

    let dir = work_dir()?;
    let local = dir.join(format!("{package}.apk"));
    run(
        Command::new("adb")
            .args(["-s", serial, "pull", remote])
            .arg(&local),
        "adb pull",
    )?;
    Ok(local.to_string_lossy().to_string())
}

// ─── Patch pipeline ───────────────────────────────────────────────────────────

fn run_patch(app: &AppHandle, opts: PatchOpts) -> Result<PatchResult, String> {
    let apk = validate_apk_path(&opts.apk_path)?;
    let mut warnings = Vec::new();
    let dir = work_dir()?;
    let stem = apk
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "app".to_string());
    let decode_dir = dir.join(format!("{stem}-decoded"));
    let built = dir.join(format!("{stem}-built.apk"));
    let aligned = dir.join(format!("{stem}-aligned.apk"));
    let signed = dir.join(format!("{stem}-patched.apk"));

    // 1. Decode --------------------------------------------------------------
    progress(app, "decode", "Decompiling APK with apktool…");
    let _ = std::fs::remove_dir_all(&decode_dir); // -f also forces, this is belt-and-suspenders
    run(
        tool("apktool")
            .arg("d")
            .arg("-f")
            .arg("-o")
            .arg(&decode_dir)
            .arg(&apk),
        "apktool decode",
    )?;

    // 2. Network security config + embedded CA -------------------------------
    progress(app, "inject", "Injecting network security config…");
    let xml_dir = decode_dir.join("res").join("xml");
    std::fs::create_dir_all(&xml_dir).map_err(|e| format!("create res/xml: {e}"))?;

    let mut anchors = String::from("      <certificates src=\"system\"/>\n");
    let mut trust_user_store = opts.trust_user_store;
    if opts.embed_proxy_ca {
        match copy_proxy_ca(&decode_dir) {
            Ok(()) => anchors.push_str("      <certificates src=\"@raw/proxy_ca\"/>\n"),
            Err(e) => {
                warnings.push(format!(
                    "Could not embed proxy CA ({e}); falling back to user store trust. \
                     Install the CA on the device manually."
                ));
                trust_user_store = true;
            }
        }
    }
    if trust_user_store {
        anchors.push_str("      <certificates src=\"user\"/>\n");
    }
    if !opts.embed_proxy_ca && !trust_user_store {
        warnings.push(
            "Neither embedded CA nor user-store trust selected — the app will not \
             trust the proxy. Enable one of them."
                .to_string(),
        );
    }

    let nsc = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <network-security-config>\n\
         \x20 <base-config cleartextTrafficPermitted=\"true\">\n\
         \x20   <trust-anchors>\n{anchors}    </trust-anchors>\n\
         \x20 </base-config>\n\
         </network-security-config>\n"
    );
    std::fs::write(xml_dir.join("network_security_config.xml"), nsc)
        .map_err(|e| format!("write nsc: {e}"))?;

    // 3. Manifest edits ------------------------------------------------------
    progress(app, "manifest", "Patching AndroidManifest.xml…");
    let manifest_path = decode_dir.join("AndroidManifest.xml");
    let manifest =
        std::fs::read_to_string(&manifest_path).map_err(|e| format!("read manifest: {e}"))?;
    let mut patched = upsert_application_attr(
        &manifest,
        "android:networkSecurityConfig",
        "@xml/network_security_config",
    )?;
    if opts.make_debuggable {
        patched = upsert_application_attr(&patched, "android:debuggable", "true")?;
    }
    std::fs::write(&manifest_path, patched).map_err(|e| format!("write manifest: {e}"))?;

    // Config-level pins are gone (we overwrote the nsc); warn about code pins.
    if opts.inject_frida {
        progress(app, "frida", "Injecting Frida gadget…");
        match inject_frida(&decode_dir, &opts.frida_gadget_path, &opts.frida_abi) {
            Ok(notes) => warnings.extend(notes),
            Err(e) => return Err(format!("Frida injection failed: {e}")),
        }
    } else {
        warnings.push(
            "Config-based cert pinning removed. Code-level/native pinning (OkHttp \
             CertificatePinner, BoringSSL) is NOT removed — enable Frida injection if \
             the app pins in code."
                .to_string(),
        );
    }

    // 4. Rebuild -------------------------------------------------------------
    progress(app, "build", "Rebuilding APK…");
    let _ = std::fs::remove_file(&built);
    run(
        tool("apktool")
            .arg("b")
            .arg("-o")
            .arg(&built)
            .arg(&decode_dir),
        "apktool build",
    )?;

    // 5. Align ---------------------------------------------------------------
    progress(app, "align", "Aligning…");
    let _ = std::fs::remove_file(&aligned);
    run(
        Command::new("zipalign")
            .args(["-p", "-f", "4"])
            .arg(&built)
            .arg(&aligned),
        "zipalign",
    )?;

    // 6. Sign ----------------------------------------------------------------
    progress(app, "sign", "Signing with debug key…");
    let (keystore, pass) = ensure_signing_keystore()?;
    let _ = std::fs::remove_file(&signed);
    run(
        tool("apksigner")
            .args(["sign", "--ks"])
            .arg(&keystore)
            .args(["--ks-pass", &format!("pass:{pass}"), "--ks-key-alias", "mitm"])
            .arg("--out")
            .arg(&signed)
            .arg(&aligned),
        "apksigner",
    )?;

    progress(app, "done", "Patch complete.");
    Ok(PatchResult {
        output_path: signed.to_string_lossy().to_string(),
        warnings,
    })
}

/// Copy the proxy's `ca-cert.pem` into the decoded tree as `res/raw/proxy_ca.pem`
/// so it can be referenced as `@raw/proxy_ca`.
fn copy_proxy_ca(decode_dir: &Path) -> Result<(), String> {
    let ca = data_dir()?.join("ca-cert.pem");
    if !ca.exists() {
        return Err("ca-cert.pem not found (start the proxy once to generate it)".into());
    }
    let raw_dir = decode_dir.join("res").join("raw");
    std::fs::create_dir_all(&raw_dir).map_err(|e| format!("create res/raw: {e}"))?;
    std::fs::copy(&ca, raw_dir.join("proxy_ca.pem")).map_err(|e| format!("copy CA: {e}"))?;
    Ok(())
}

/// Generate (once) a local debug keystore used to re-sign patched APKs. This is
/// a throwaway signing identity — patched APKs cannot update Play installs.
fn ensure_signing_keystore() -> Result<(PathBuf, String), String> {
    let keystore = data_dir()?.join("apk-sign.jks");
    let pass = "mitm-patcher".to_string();
    if !keystore.exists() {
        run(
            Command::new("keytool")
                .args(["-genkeypair", "-v", "-keyalg", "RSA", "-keysize", "2048"])
                .args(["-validity", "10000", "-alias", "mitm"])
                .args(["-storepass", &pass, "-keypass", &pass])
                .args(["-dname", "CN=MITM Patcher, O=PacketSniffer"])
                .arg("-keystore")
                .arg(&keystore),
            "keytool genkeypair",
        )?;
    }
    Ok((keystore, pass))
}

// ─── XML manifest editing (no external XML dep) ───────────────────────────────

/// Set `attr="value"` on the `<application>` tag, replacing an existing value if
/// the attribute is already present. Returns an error if the manifest has no
/// editable application tag (e.g., self-closing or malformed).
fn upsert_application_attr(manifest: &str, attr: &str, value: &str) -> Result<String, String> {
    let needle = format!("{attr}=\"");
    if let Some(start) = manifest.find(&needle) {
        let val_start = start + needle.len();
        if let Some(rel_end) = manifest[val_start..].find('"') {
            let val_end = val_start + rel_end;
            let mut s = String::with_capacity(manifest.len());
            s.push_str(&manifest[..val_start]);
            s.push_str(value);
            s.push_str(&manifest[val_end..]);
            return Ok(s);
        }
    }
    // Insert into the opening <application ...> tag.
    if let Some(app_idx) = manifest.find("<application") {
        let after = app_idx + "<application".len();
        if let Some(rel_gt) = manifest[after..].find('>') {
            let gt = after + rel_gt;
            let insert = format!(" {attr}=\"{value}\"");
            let mut s = String::with_capacity(manifest.len() + insert.len());
            s.push_str(&manifest[..gt]);
            s.push_str(&insert);
            s.push_str(&manifest[gt..]);
            return Ok(s);
        }
    }
    Err("Manifest has no editable <application> tag (self-closing or malformed)".to_string())
}

// ─── Frida gadget injection ───────────────────────────────────────────────────
// Places libfrida-gadget.so in the right ABI dir and forces the app to load it
// by injecting `System.loadLibrary("frida-gadget")` into the launcher activity's
// static initializer. Best-effort: returns notes/warnings for the caller.

fn inject_frida(decode_dir: &Path, gadget_path: &str, abi_pref: &str) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    let gadget = PathBuf::from(gadget_path);
    if !gadget.is_file() {
        return Err(format!(
            "gadget .so not found: '{gadget_path}'. Supply a libfrida-gadget.so matching the device ABI."
        ));
    }

    // 1. Choose ABI dir. Prefer an explicit choice, else an ABI already present,
    //    preferring arm64-v8a (most modern devices).
    const KNOWN_ABIS: &[&str] = &["armeabi-v7a", "arm64-v8a", "x86", "x86_64"];
    let lib_root = decode_dir.join("lib");
    let present: Vec<String> = std::fs::read_dir(&lib_root)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();

    let abi = if !abi_pref.is_empty() && abi_pref != "auto" {
        // Validate against known ABIs to prevent path traversal
        if !KNOWN_ABIS.contains(&abi_pref.as_str()) {
            return Err(format!(
                "Invalid ABI '{}'. Must be one of: {}",
                abi_pref,
                KNOWN_ABIS.join(", ")
            ));
        }
        abi_pref.to_string()
    } else if present.iter().any(|a| a == "arm64-v8a") {
        "arm64-v8a".to_string()
    } else if let Some(first) = present.iter().find(|a| KNOWN_ABIS.contains(&a.as_str())) {
        first.clone()
    } else {
        notes.push("APK has no native lib dir — created lib/arm64-v8a; ensure your gadget is arm64.".to_string());
        "arm64-v8a".to_string()
    };
    if !present.is_empty() && !present.contains(&abi) {
        notes.push(format!(
            "Chosen ABI '{abi}' not among APK's existing ABIs ({}). Gadget may not load if it mismatches the device.",
            present.join(", ")
        ));
    }

    // 2. Drop the gadget in as libfrida-gadget.so.
    let abi_dir = lib_root.join(&abi);
    std::fs::create_dir_all(&abi_dir).map_err(|e| format!("create lib/{abi}: {e}"))?;
    std::fs::copy(&gadget, abi_dir.join("libfrida-gadget.so"))
        .map_err(|e| format!("copy gadget: {e}"))?;

    // 3. Force-load it from the launcher activity's <clinit>.
    let manifest =
        std::fs::read_to_string(decode_dir.join("AndroidManifest.xml")).map_err(|e| e.to_string())?;
    let pkg = attr_value(&manifest, "package").unwrap_or_default();
    let launcher = find_launcher_class(&manifest, &pkg)
        .ok_or("could not find launcher activity in manifest")?;
    let smali_path = resolve_smali(decode_dir, &launcher)
        .ok_or_else(|| format!("smali for launcher '{launcher}' not found"))?;

    let smali = std::fs::read_to_string(&smali_path).map_err(|e| e.to_string())?;
    let patched = if smali.contains(".method static constructor <clinit>()V") {
        inject_into_clinit(&smali, "frida-gadget")
            .ok_or("failed to patch existing <clinit> of launcher activity")?
    } else {
        add_fresh_clinit(&smali, "frida-gadget")
    };
    std::fs::write(&smali_path, patched).map_err(|e| e.to_string())?;

    notes.push(format!(
        "Frida gadget injected into {} (lib/{abi}). Connect with `frida -U Gadget`.",
        launcher
    ));
    Ok(notes)
}

/// Find the launcher activity's fully-qualified class from the manifest.
fn find_launcher_class(manifest: &str, pkg: &str) -> Option<String> {
    // Split into per-component chunks and find the one declaring MAIN + LAUNCHER.
    for chunk in split_components(manifest) {
        if chunk.contains("android.intent.action.MAIN")
            && chunk.contains("android.intent.category.LAUNCHER")
        {
            // activity-alias points at a target activity; plain activity uses its own name.
            let raw = attr_value(chunk, "android:targetActivity")
                .or_else(|| attr_value(chunk, "android:name"))?;
            return Some(qualify(&raw, pkg));
        }
    }
    None
}

/// Yield substrings each starting at an `<activity` / `<activity-alias` tag.
fn split_components(manifest: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = manifest;
    let mut search = 0;
    while let Some(rel) = bytes[search..].find("<activity") {
        let start = search + rel;
        // end at the next component or close of application
        let rest = &bytes[start + 1..];
        let end_rel = ["<activity", "</application"]
            .iter()
            .filter_map(|m| rest.find(m))
            .min()
            .unwrap_or(rest.len());
        out.push(&bytes[start..start + 1 + end_rel]);
        search = start + 1 + end_rel;
    }
    out
}

/// Read `name="value"` from a tag/manifest chunk.
fn attr_value<'a>(s: &'a str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = s.find(&needle)? + needle.len();
    let end = s[start..].find('"')? + start;
    Some(s[start..end].to_string())
}

/// Resolve a class name (possibly relative) against the package.
fn qualify(name: &str, pkg: &str) -> String {
    if let Some(rest) = name.strip_prefix('.') {
        format!("{pkg}.{rest}")
    } else if name.contains('.') {
        name.to_string()
    } else {
        format!("{pkg}.{name}")
    }
}

/// Locate the `.smali` file for a class across smali/ smali_classes2/ … dirs.
fn resolve_smali(decode_dir: &Path, class: &str) -> Option<PathBuf> {
    let rel = format!("{}.smali", class.replace('.', "/"));
    let entries = std::fs::read_dir(decode_dir).ok()?;
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "smali" || name.starts_with("smali_classes") {
            let candidate = entry.path().join(&rel);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Insert the loadLibrary call at the top of an existing `<clinit>` body.
fn inject_into_clinit(smali: &str, lib: &str) -> Option<String> {
    let marker = ".method static constructor <clinit>()V";
    let mstart = smali.find(marker)?;
    let after = mstart + marker.len();
    let mend = after + smali[after..].find(".end method")?;
    let (head, body, tail) = (&smali[..after], &smali[after..mend], &smali[mend..]);

    let inject = format!(
        "    const-string v0, \"{lib}\"\n    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
    );
    let mut new_body = String::with_capacity(body.len() + inject.len() + 16);
    let mut injected = false;
    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if !injected && (trimmed.starts_with(".locals ") || trimmed.starts_with(".registers ")) {
            let kw = if trimmed.starts_with(".locals") { ".locals" } else { ".registers" };
            let n: u32 = trimmed[kw.len()..].trim().parse().ok()?;
            new_body.push_str(&format!("    {kw} {}\n", n.max(1)));
            new_body.push_str(&inject);
            injected = true;
        } else {
            new_body.push_str(line);
        }
    }
    injected.then(|| format!("{head}{new_body}{tail}"))
}

/// Append a fresh `<clinit>` that loads the gadget.
fn add_fresh_clinit(smali: &str, lib: &str) -> String {
    let method = format!(
        ".method static constructor <clinit>()V\n    .locals 1\n    const-string v0, \"{lib}\"\n    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n    return-void\n.end method\n\n"
    );
    match smali.find("\n.method ") {
        Some(idx) => format!("{}{}{}", &smali[..idx + 1], method, &smali[idx + 1..]),
        None => format!("{smali}\n{method}"),
    }
}

// ─── Paths, validation, process helpers ───────────────────────────────────────

fn data_dir() -> Result<PathBuf, String> {
    directories::ProjectDirs::from("com", "packetsniffer", "PacketSniffer")
        .map(|d| d.data_dir().to_path_buf())
        .ok_or_else(|| "Cannot determine data directory".to_string())
}

fn work_dir() -> Result<PathBuf, String> {
    let dir = data_dir()?.join("apk-work");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create work dir: {e}"))?;
    Ok(dir)
}

fn validate_apk_path(path: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(path);
    if !p.is_file() {
        return Err(format!("APK not found: {path}"));
    }
    if p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("apk")) != Some(true) {
        return Err("File is not a .apk".to_string());
    }
    Ok(p)
}

/// adb serials: alphanumerics plus `.:_-` (covers emulator-5554 and network adb host:port).
fn validate_serial(serial: &str) -> Result<(), String> {
    if serial.is_empty()
        || !serial
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-'))
    {
        return Err("Invalid device serial".to_string());
    }
    Ok(())
}

/// Android package names: alphanumerics plus `._`.
fn validate_package(pkg: &str) -> Result<(), String> {
    if pkg.is_empty()
        || !pkg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_'))
    {
        return Err("Invalid package name".to_string());
    }
    Ok(())
}

fn progress(app: &AppHandle, stage: &str, message: &str) {
    let _ = app.emit(
        "apk-patch-progress",
        PatchProgress {
            stage: stage.to_string(),
            message: message.to_string(),
        },
    );
}

/// Build a Command for an external tool. On Windows, route through `cmd /C` so
/// batch-wrapper tools (apktool, apksigner are `.bat`/`.cmd`) actually launch —
/// `Command::new` only resolves `.exe` and would fail to start them.
fn tool(bin: &str) -> Command {
    #[cfg(target_os = "windows")]
    {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(bin);
        c
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new(bin)
    }
}

/// Run a command, returning stdout on success or a stderr-derived error.
/// All arguments are passed as an argv array (no shell), so device serials and
/// package names cannot inject extra commands.
///
/// TODO: Add timeout support using tokio::time::timeout to prevent indefinite hangs.
/// Example implementation:
/// ```ignore
/// use tokio::time::{timeout, Duration};
/// let result = timeout(Duration::from_secs(60), async {
///     tokio::task::spawn_blocking(move || cmd.output()).await
/// }).await;
/// ```
fn run(cmd: &mut Command, ctx: &str) -> Result<String, String> {
    let out = cmd
        .output()
        .map_err(|e| format!("{ctx}: failed to launch ({e}) — is it installed and on PATH?"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let detail = if stderr.trim().is_empty() { stdout } else { stderr };
        Err(format!("{ctx} failed: {}", detail.trim()))
    }
}
