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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProtection {
    /// App is wrapped in Google Play Automatic Integrity Protection (PAIRIP) —
    /// repackaging can't work (see `run_patch`'s refusal), so the UI flags it.
    pub pairip: bool,
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
    /// Run the gadget in *script mode*: bundle a Frida script + gadget config
    /// inside the APK so the script auto-runs on launch, with NO PC-side `frida`
    /// attach. When false the gadget runs in listen mode (waits for a
    /// `frida -U Gadget` connection). Ignored unless `inject_frida` is set.
    #[serde(default)]
    pub frida_script_mode: bool,
    /// Path to a custom Frida `.js` script to bundle in script mode. Empty ⇒ a
    /// built-in generic anti-tamper bypass is used. Only read when both
    /// `inject_frida` and `frida_script_mode` are set.
    #[serde(default)]
    pub frida_script_path: String,
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
        no_window(Command::new("where").arg(bin))
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

/// Probe whether an installed app is PAIRIP-protected, so the UI can flag it
/// before the user attempts a patch that can't work. Cheap: inspects the app's
/// on-device APKs (zip central directory only) rather than pulling them.
#[tauri::command]
pub async fn check_app_protection(serial: String, package: String) -> Result<AppProtection, String> {
    validate_serial(&serial)?;
    validate_package(&package)?;
    tokio::task::spawn_blocking(move || {
        Ok(AppProtection {
            pairip: device_has_pairip(&serial, &package),
        })
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

/// Pull a package's APKs off a device into the working directory and return the
/// base APK's local path. For split-APK apps the config splits are pulled too
/// (as `{pkg}.split.*`) so the patched app can be reinstalled as a complete set.
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

/// Outcome of a non-destructive install attempt.
/// - `status = "installed"`: the app went on cleanly, no data touched.
/// - `status = "needsReplace"`: the on-device app is signed differently, so an
///   in-place update is impossible. Replacing it wipes its data — the caller must
///   confirm with the user and then call [`replace_patched_apk`].
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallOutcome {
    pub status: String,
    pub message: String,
}

/// Install a patched APK on a device WITHOUT ever erasing data. `-r` updates in
/// place and `-t` allows test/debuggable packages. For split-APK apps the patched
/// base is installed together with its (re-signed) config splits via
/// `install-multiple`. If the signature clashes (the patched APK is re-signed with
/// our debug key, so it can't update a store-signed install), Android refuses and
/// leaves the existing app untouched — we report `needsReplace` so the user can
/// decide, rather than silently wiping data.
#[tauri::command]
pub async fn install_patched_apk(
    serial: String,
    apk_path: String,
    package: Option<String>,
) -> Result<InstallOutcome, String> {
    validate_serial(&serial)?;
    let apk = validate_apk_path(&apk_path)?;
    if let Some(p) = &package {
        validate_package(p)?;
    }
    tokio::task::spawn_blocking(move || {
        let apks = collect_install_apks(&apk, package.as_deref())?;
        let first = adb_install(&serial, &apks, true);
        match first {
            Ok(_) => Ok(InstallOutcome {
                status: "installed".to_string(),
                message: "Installed".to_string(),
            }),
            Err(e) => {
                let sig_conflict = e.contains("signatures do not match")
                    || e.contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE");
                if sig_conflict && package.is_some() {
                    // Non-destructive update failed. Hand the decision to the user;
                    // `replace_patched_apk` does the data-wiping reinstall once confirmed.
                    Ok(InstallOutcome {
                        status: "needsReplace".to_string(),
                        message: "The app already on the phone is signed differently \
                                  (e.g. the Play Store build). Installing the patched \
                                  version requires uninstalling the original first, \
                                  which erases its data."
                            .to_string(),
                    })
                } else if sig_conflict {
                    Err(format!(
                        "{e}\nThe patched app is signed differently than the one on the phone — \
                         uninstall the original app, then retry."
                    ))
                } else {
                    Err(e)
                }
            }
        }
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

/// Uninstall the on-device app, then install the patched APK fresh. This ERASES
/// the app's existing data, so only call it after the user has confirmed (i.e.
/// after [`install_patched_apk`] returned `needsReplace`).
#[tauri::command]
pub async fn replace_patched_apk(
    serial: String,
    apk_path: String,
    package: String,
) -> Result<String, String> {
    validate_serial(&serial)?;
    let apk = validate_apk_path(&apk_path)?;
    validate_package(&package)?;
    tokio::task::spawn_blocking(move || {
        let apks = collect_install_apks(&apk, Some(&package))?;
        // Uninstall may fail if the app isn't actually present — ignore and install.
        let _ = run(
            Command::new("adb").args(["-s", &serial, "uninstall", &package]),
            "adb uninstall",
        );
        adb_install(&serial, &apks, false)
            .map(|_| "Installed (replaced the original app; its data was cleared)".to_string())
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
}

/// Run `adb install` (single APK) or `adb install-multiple` (base + splits).
/// `replace` adds `-r` for an in-place update; `-t` always allows test/debuggable
/// packages. All entries must share one signing key (we re-sign splits to match).
fn adb_install(serial: &str, apks: &[PathBuf], replace: bool) -> Result<String, String> {
    let mut cmd = Command::new("adb");
    cmd.args(["-s", serial]);
    cmd.arg(if apks.len() > 1 {
        "install-multiple"
    } else {
        "install"
    });
    if replace {
        cmd.arg("-r");
    }
    cmd.arg("-t");
    // Spoof the installer package so apps that gate on install source
    // (`getInstallerPackageName` / `getInstallSourceInfo`) believe they came from
    // the Play Store instead of adb. Defeats the cheap "installed from Google
    // Play?" check; cryptographic checks (Play Integrity) are unaffected — see
    // patch_apk warnings, those need a Frida hook on the verdict.
    cmd.args(["-i", "com.android.vending"]);
    for a in apks {
        cmd.arg(a);
    }
    run(&mut cmd, "adb install")
}

/// Build the APK set to install: the patched base plus any sibling config splits
/// pulled alongside it (named `{pkg}.split.*`). Splits are re-signed with our debug
/// key so the whole set shares one signature — Android rejects a mixed-signer set.
/// Returns just `[base]` when there are no splits (e.g. a lone file picked off disk).
fn collect_install_apks(patched_base: &Path, package: Option<&str>) -> Result<Vec<PathBuf>, String> {
    let mut apks = vec![patched_base.to_path_buf()];
    let pkg = match package {
        Some(p) => p,
        None => return Ok(apks),
    };
    let dir = work_dir()?;
    let prefix = format!("{pkg}.split.");
    let mut splits: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| format!("read work dir: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(&prefix) && n.ends_with(".apk") && !n.contains("-resigned"))
                .unwrap_or(false)
        })
        .collect();
    if splits.is_empty() {
        return Ok(apks);
    }
    splits.sort();

    let (keystore, pass) = ensure_signing_keystore()?;
    for split in &splits {
        let stem = split.file_stem().and_then(|s| s.to_str()).unwrap_or("split");
        let signed = dir.join(format!("{stem}-resigned.apk"));
        align_and_sign(split, &signed, &keystore, &pass)?;
        apks.push(signed);
    }
    Ok(apks)
}

/// Zipalign then re-sign an APK with our debug key (no manifest edits). Used for
/// config splits, which only need a signature matching the patched base.
fn align_and_sign(input: &Path, out: &Path, keystore: &Path, pass: &str) -> Result<(), String> {
    let dir = work_dir()?;
    let stem = out.file_stem().and_then(|s| s.to_str()).unwrap_or("split");
    let aligned = dir.join(format!("{stem}.aligned.apk"));
    let _ = std::fs::remove_file(&aligned);
    run(
        Command::new("zipalign")
            .args(["-p", "-f", "4"])
            .arg(input)
            .arg(&aligned),
        "zipalign split",
    )?;
    let _ = std::fs::remove_file(out);
    run(
        tool("apksigner")
            .args(["sign", "--ks"])
            .arg(keystore)
            .args(["--ks-pass", &format!("pass:{pass}"), "--ks-key-alias", "mitm"])
            .arg("--out")
            .arg(out)
            .arg(&aligned),
        "apksigner split",
    )?;
    let _ = std::fs::remove_file(&aligned);
    Ok(())
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
    let has_winget = no_window(Command::new("winget").arg("--version")).output().is_ok();

    if missing.iter().any(|t| t == "java" || t == "keytool") {
        if has_winget {
            tools_progress(app, "install", "Installing OpenJDK via winget…");
            // Pin `--source winget`: a broken msstore source otherwise makes
            // winget bail with "specify one of them using --source".
            let _ = no_window(Command::new("winget").args([
                "install", "-e", "--id", "Microsoft.OpenJDK.17",
                "--source", "winget", "--silent",
                "--accept-source-agreements", "--accept-package-agreements",
            ]))
            .status();
            // The installer updates machine PATH, but our process won't see it
            // until restart — add the JDK's bin dir to PATH now.
            add_winget_jdk_to_path();
        }
        // Judge by whether java actually resolves, not winget's exit code
        // (it returns non-zero for "already installed" and other benign cases).
        if no_window(Command::new("java").arg("-version")).output().is_ok() {
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
    let _ = no_window(
        Command::new("adb")
            .args(["-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0"]),
    )
    .output();
    let tcp = format!("tcp:{port}");
    let _ = no_window(
        Command::new("adb").args(["-s", serial, "reverse", "--remove", tcp.as_str()]),
    )
    .output();
}

fn download_platform_tools(app: &AppHandle) -> Result<String, String> {
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let url = format!("https://dl.google.com/android/repository/platform-tools-latest-{os}.zip");
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
    let out = no_window(Command::new("powershell").args([
        "-NoProfile",
        "-Command",
        "[Environment]::ExpandEnvironmentVariables((@([Environment]::GetEnvironmentVariable('Path','Machine'),[Environment]::GetEnvironmentVariable('Path','User')) -join ';'))",
    ]))
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

/// True if any of the package's on-device APKs contains `libpairipcore.so` (the
/// PAIRIP native VM). Uses `unzip -l` (reads the zip central directory only — fast
/// even for a 100 MB base) over adb. Best-effort: any failure ⇒ false, so a flaky
/// probe never blocks the user (run_patch still refuses PAIRIP as the backstop).
fn device_has_pairip(serial: &str, package: &str) -> bool {
    let Ok(out) = run(
        Command::new("adb").args(["-s", serial, "shell", "pm", "path", package]),
        "pm path",
    ) else {
        return false;
    };
    for line in out.lines() {
        let Some(path) = line.trim().strip_prefix("package:") else {
            continue;
        };
        let path = path.trim();
        // Paths come from the package manager, but stay defensive: only shell-safe
        // characters, so the single-quoted path below can't break out of its quotes.
        if path.is_empty()
            || !path.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~' | '=' | '+')
            })
        {
            continue;
        }
        let probe = format!("unzip -l '{path}' 2>/dev/null | grep -c libpairipcore.so");
        if let Ok(res) = run(
            Command::new("adb").args(["-s", serial, "shell", &probe]),
            "pairip probe",
        ) {
            let count: u32 = res.trim().lines().next().unwrap_or("0").trim().parse().unwrap_or(0);
            if count > 0 {
                return true;
            }
        }
    }
    false
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
    // Prefer base.apk; fall back to the first entry.
    let base = remote_paths
        .iter()
        .find(|p| p.ends_with("base.apk"))
        .copied()
        .unwrap_or(remote_paths[0]);

    let dir = work_dir()?;

    // Clear stale splits from a previous pull so the install set can't include
    // leftovers from a different version/app.
    let split_prefix = format!("{package}.split.");
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.filter_map(|e| e.ok()) {
            if e.file_name().to_string_lossy().starts_with(&split_prefix) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    let local = dir.join(format!("{package}.apk"));
    run(
        Command::new("adb")
            .args(["-s", serial, "pull", base])
            .arg(&local),
        "adb pull",
    )?;

    // Pull the config splits too (everything that isn't the base). The patched app
    // is installed as the complete set via `install-multiple`; installing the base
    // alone fails with INSTALL_FAILED_MISSING_SPLIT.
    for remote in &remote_paths {
        if *remote == base {
            continue;
        }
        // Last path component only (no slashes) → stays inside the work dir.
        let fname = remote.rsplit('/').next().unwrap_or(remote);
        let split_local = dir.join(format!("{package}.split.{fname}"));
        run(
            Command::new("adb")
                .args(["-s", serial, "pull", remote])
                .arg(&split_local),
            "adb pull split",
        )?;
    }

    Ok(local.to_string_lossy().to_string())
}

// ─── Patch pipeline ───────────────────────────────────────────────────────────

fn run_patch(app: &AppHandle, opts: PatchOpts) -> Result<PatchResult, String> {
    let apk = validate_apk_path(&opts.apk_path)?;
    // Refuse PAIRIP apps up front — repackaging fundamentally can't work on them.
    if detect_pairip(&apk) {
        return Err(
            "This app uses Google Play Automatic Integrity Protection (PAIRIP): its code is \
             virtualized and libpairipcore.so verifies integrity in native code, so any re-sign \
             trips it — the app redirects to the Play Store and exits. Repackaging cannot bypass \
             this. To capture its traffic, use a rooted device with the proxy CA installed as a \
             system certificate (keeping the original Play-signed app), plus Frida for any extra \
             pinning."
                .to_string(),
        );
    }
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
    // Force native libs to be extracted to the filesystem at install time. A modern
    // APK ships its `.so` files uncompressed and page-aligned and sets
    // `android:extractNativeLibs="false"` so Android mmaps them straight from the
    // APK. apktool's rebuild re-compresses those entries, and `zipalign -p` can only
    // page-align *stored* (uncompressed) entries — so the rebuilt libs end up
    // compressed and the installer rejects the APK (INSTALL_FAILED_INVALID_APK:
    // "Failed to extract native libraries, res=-2"). Setting this to "true" drops
    // the uncompressed+aligned requirement entirely. Harmless no-op for APKs with no
    // native libs, and also unblocks a Frida gadget injected into such an app.
    patched = upsert_application_attr(&patched, "android:extractNativeLibs", "true")?;
    // apktool can decode a `<meta-data>` value it doesn't understand (some typed
    // values, `@null`, refs into a split) as a name-only element. aapt2 then
    // rebuilds it without a value, and Android's package parser rejects the APK
    // (INSTALL_PARSE_FAILED_MANIFEST_MALFORMED: "<meta-data> requires an
    // android:value or android:resource attribute"). Give any such orphan an
    // empty value so the manifest parses; the original value was already lost in
    // decode, so empty is no worse and unblocks install.
    let (patched, repaired) = fix_orphan_meta_data(&patched);
    if repaired > 0 {
        warnings.push(format!(
            "Repaired {repaired} <meta-data> element(s) that apktool decoded without a \
             value (gave them android:value=\"\") so the APK installs. If the app reads \
             one of these, its behavior may differ from the original."
        ));
    }
    std::fs::write(&manifest_path, patched).map_err(|e| format!("write manifest: {e}"))?;

    // Config-level pins are gone (we overwrote the nsc); warn about code pins.
    if opts.inject_frida {
        progress(app, "frida", "Injecting Frida gadget…");
        match inject_frida(
            &decode_dir,
            &opts.frida_gadget_path,
            &opts.frida_abi,
            opts.frida_script_mode,
            &opts.frida_script_path,
            &apk,
        ) {
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

/// Google Play Automatic Integrity Protection (PAIRIP) wraps the app in a native
/// VM (`libpairipcore.so`) and verifies integrity in native code, redirecting to
/// the Play "license paywall" and exiting on any re-sign — so repackaging can
/// never work. The native lib ships in the arm64/abi *config split*, not base, so
/// scan the base APK and its sibling config splits. Matches the marker filename
/// in the raw zip bytes (stored uncompressed in the local/central headers), which
/// avoids a full zip parse.
fn detect_pairip(base_apk: &Path) -> bool {
    const MARKER: &[u8] = b"libpairipcore.so";
    if file_contains(base_apk, MARKER) {
        return true;
    }
    let (Some(dir), Some(stem)) = (
        base_apk.parent(),
        base_apk.file_stem().and_then(|s| s.to_str()),
    ) else {
        return false;
    };
    // Config splits are pulled alongside the base as `{stem}.split.*` (see pull_base_apk).
    let prefix = format!("{stem}.split.");
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    for e in rd.filter_map(|e| e.ok()) {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".apk") && file_contains(&e.path(), MARKER) {
            return true;
        }
    }
    false
}

/// True if `path`'s bytes contain `needle`. Reads the whole file — a one-time
/// patch pre-check, fine for APK-sized inputs.
fn file_contains(path: &Path, needle: &[u8]) -> bool {
    match std::fs::read(path) {
        Ok(bytes) => bytes.windows(needle.len()).any(|w| w == needle),
        Err(_) => false,
    }
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

/// Normalize every `<meta-data>` that Android's installer would reject for
/// lacking a usable value. apktool 3.0.x can emit three bad shapes for a value
/// it couldn't decode: name-only (no value/resource at all), or an explicit
/// `android:value="@null"` / `android:resource="@null"`. aapt2 compiles the
/// `@null` forms to a TYPE_NULL attribute, which the package parser treats as
/// *missing* — same `INSTALL_PARSE_FAILED_MANIFEST_MALFORMED` as the name-only
/// case. All three are rewritten to a present, empty `android:value=""`. The
/// real value was already lost in decode, so empty is no worse and unblocks the
/// install. Returns the patched manifest and the count of tags repaired.
fn fix_orphan_meta_data(manifest: &str) -> (String, usize) {
    let mut out = String::with_capacity(manifest.len());
    let mut rest = manifest;
    let mut repaired = 0;
    while let Some(rel) = rest.find("<meta-data") {
        // Copy through the start of the tag.
        out.push_str(&rest[..rel]);
        rest = &rest[rel..];
        // Find this tag's closing '>'. apktool keeps each tag on one line, but a
        // stray '>' can't appear inside the unquoted attribute area, so the first
        // '>' is the tag end.
        let Some(gt) = rest.find('>') else {
            // Malformed tail — emit verbatim and stop.
            out.push_str(rest);
            rest = "";
            break;
        };
        let tag = &rest[..=gt];
        rest = &rest[gt + 1..];

        // Valid iff a value or resource is present and not "@null". An empty
        // string (android:value="") is present, so it's fine — never re-touch it
        // (that would duplicate the attribute).
        if meta_attr_present(tag, "android:value") || meta_attr_present(tag, "android:resource") {
            out.push_str(tag);
            continue;
        }
        let new_tag = if tag.contains("android:value=\"@null\"") {
            tag.replace("android:value=\"@null\"", "android:value=\"\"")
        } else if tag.contains("android:resource=\"@null\"") {
            // A null resource can't be made a real resource ref; downgrade to an
            // empty value, which satisfies the parser.
            tag.replace("android:resource=\"@null\"", "android:value=\"\"")
        } else {
            // Name-only: insert before the self-closing '/' if present, else '>'.
            // Test the byte right before '>' so a '/' inside an attribute value
            // (e.g. android:name="a/b") can't be mistaken for the tag's slash.
            let insert_at = if gt > 0 && tag.as_bytes()[gt - 1] == b'/' {
                gt - 1
            } else {
                gt
            };
            format!("{} android:value=\"\"{}", &tag[..insert_at], &tag[insert_at..])
        };
        out.push_str(&new_tag);
        repaired += 1;
    }
    out.push_str(rest);
    (out, repaired)
}

/// True if `attr` appears on the tag with a real value — present and not the
/// literal `@null` apktool writes for a null-decoded value. An empty string
/// counts as present (the installer only requires the attribute to exist).
fn meta_attr_present(tag: &str, attr: &str) -> bool {
    let needle = format!("{attr}=\"");
    let Some(s) = tag.find(&needle) else {
        return false;
    };
    let s = s + needle.len();
    let Some(e) = tag[s..].find('"') else {
        return false;
    };
    &tag[s..s + e] != "@null"
}

#[cfg(test)]
mod meta_data_tests {
    use super::fix_orphan_meta_data;

    #[test]
    fn rewrites_null_resource() {
        // The exact shape that broke net.cncapps.hackex2 at install (line #90).
        let src = r#"<meta-data android:name="com.google.firebase.messaging.default_notification_icon" android:resource="@null"/>"#;
        let (out, n) = fix_orphan_meta_data(src);
        assert_eq!(n, 1);
        assert!(out.contains(r#"android:value="""#), "got: {out}");
        assert!(!out.contains("@null"), "got: {out}");
    }

    #[test]
    fn rewrites_null_value_and_name_only() {
        let src = concat!(
            r#"<meta-data android:name="a" android:value="@null"/>"#,
            "\n",
            r#"<meta-data android:name="b"/>"#,
        );
        let (out, n) = fix_orphan_meta_data(src);
        assert_eq!(n, 2);
        assert!(!out.contains("@null"));
        assert_eq!(out.matches(r#"android:value="""#).count(), 2, "got: {out}");
    }

    #[test]
    fn leaves_valid_meta_data_untouched() {
        let src = concat!(
            r#"<meta-data android:name="x" android:value="com.foo.Bar"/>"#,
            "\n",
            r#"<meta-data android:name="y" android:resource="@xml/paths"/>"#,
            "\n",
            // Empty value is already present — must not be doubled.
            r#"<meta-data android:name="z" android:value=""/>"#,
        );
        let (out, n) = fix_orphan_meta_data(src);
        assert_eq!(n, 0);
        assert_eq!(out, src);
    }
}

#[cfg(test)]
mod sig_block_tests {
    use super::v2v3_first_cert_der;

    /// u32-length-prefix `data` (little-endian) — the APK Signing Block convention.
    fn lp(data: &[u8]) -> Vec<u8> {
        let mut o = (data.len() as u32).to_le_bytes().to_vec();
        o.extend_from_slice(data);
        o
    }

    /// Wrap a signing block + EOCD around `pair_body` (id+value) so the reader
    /// finds a valid central-directory offset and magic.
    fn apk_with_pair(pair_body: &[u8]) -> Vec<u8> {
        let mut pairs = (pair_body.len() as u64).to_le_bytes().to_vec();
        pairs.extend_from_slice(pair_body);

        let block_size = (pairs.len() + 8 + 16) as u64;
        let mut block = block_size.to_le_bytes().to_vec();
        block.extend_from_slice(&pairs);
        block.extend_from_slice(&block_size.to_le_bytes());
        block.extend_from_slice(b"APK Sig Block 42");

        let prefix = vec![0u8; 8];
        let cd_offset = (prefix.len() + block.len()) as u32;
        let mut eocd = vec![0x50u8, 0x4b, 0x05, 0x06];
        eocd.extend_from_slice(&[0u8; 12]); // disk/count/cd-size (zeroed)
        eocd.extend_from_slice(&cd_offset.to_le_bytes());
        eocd.extend_from_slice(&[0u8, 0]); // comment length

        let mut apk = prefix;
        apk.extend_from_slice(&block);
        apk.extend_from_slice(&eocd);
        apk
    }

    #[test]
    fn extracts_first_cert_from_v2_block() {
        let cert: &[u8] = b"FAKE-DER-CERTIFICATE-BYTES";
        // signed data = [digests seq (empty)] [certificates seq [cert]]
        let mut signed_data = lp(&[]);
        signed_data.extend(lp(&lp(cert)));
        let value = lp(&lp(&lp(&signed_data))); // value = lp(signers = lp(signer = lp(signed_data)))

        let mut pair_body = 0x7109_871au32.to_le_bytes().to_vec(); // v2 id
        pair_body.extend_from_slice(&value);

        assert_eq!(
            v2v3_first_cert_der(&apk_with_pair(&pair_body)).as_deref(),
            Some(cert)
        );
    }

    #[test]
    fn returns_none_without_signing_block() {
        // 32-byte prefix + bare EOCD → cd_offset lands in the prefix, magic check
        // fails, so no cert is returned.
        let mut apk = vec![0u8; 32];
        let cd_offset = apk.len() as u32;
        apk.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        apk.extend_from_slice(&[0u8; 12]);
        apk.extend_from_slice(&cd_offset.to_le_bytes());
        apk.extend_from_slice(&[0u8, 0]);
        assert_eq!(v2v3_first_cert_der(&apk), None);
    }
}

#[cfg(test)]
mod pairip_tests {
    use super::detect_pairip;
    use std::fs;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pairip-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn detects_marker_in_sibling_split() {
        let dir = tmp("split");
        let base = dir.join("com.example.apk");
        fs::write(&base, b"PK\x03\x04 no marker in base").unwrap();
        assert!(!detect_pairip(&base), "clean base+no splits must not match");

        // The native lib lives in a config split, not base — must still detect.
        fs::write(
            dir.join("com.example.split.config.arm64_v8a.apk"),
            b"....lib/arm64-v8a/libpairipcore.so....",
        )
        .unwrap();
        assert!(detect_pairip(&base), "marker in sibling split must match");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_marker_in_base() {
        let dir = tmp("base");
        let base = dir.join("app.apk");
        fs::write(&base, b"zip...lib/arm64-v8a/libpairipcore.so...").unwrap();
        assert!(detect_pairip(&base));
        let _ = fs::remove_dir_all(&dir);
    }
}

// ─── Frida gadget injection ───────────────────────────────────────────────────
// Places libfrida-gadget.so in the right ABI dir and forces the app to load it
// by injecting `System.loadLibrary("frida-gadget")` into the launcher activity's
// static initializer. In *script mode* it also bundles a Frida script + gadget
// config so the script auto-runs on launch (no PC-side `frida` attach); otherwise
// the gadget runs in listen mode. Best-effort: returns notes/warnings.

/// Default Frida script bundled in script mode when the user supplies none. A
/// generic, cert-independent bypass for repackaged apps that detect the re-sign
/// and bounce to the Play Store: it swallows Play-Store redirect intents and
/// blocks the app from killing itself. App-specific pinning/integrity needs
/// custom hooks — the script carries commented scaffolds for those.
const DEFAULT_FRIDA_BYPASS: &str = r#"/*
 * PacketSniffer - default Frida bypass (Gadget script mode, auto-runs on launch).
 *
 * Generic help for a repackaged (re-signed) app that refuses to run and bounces
 * you to the Play Store ("Get this app from Play"). It does NOT need the app's
 * original signing certificate - instead it neuters the two things such apps do
 * on a failed integrity check: open the Play listing, and kill themselves.
 *
 * This is a STARTING POINT. Apps that gate features behind a server-side verdict
 * (Play Integrity) or pin certs in native code need app-specific hooks - see the
 * commented scaffolds at the bottom. Supply your own .js in the patch dialog to
 * replace this file.
 */
Java.perform(function () {
  function log(m) { console.log('[packetsniffer] ' + m); }

  // Does this intent send the user to the Play Store?
  function isPlayIntent(intent) {
    try {
      var data = intent.getDataString();
      if (data) {
        var d = data.toLowerCase();
        if (d.indexOf('play.google.com') !== -1 || d.indexOf('market://') !== -1) return true;
      }
      if (intent.getPackage() === 'com.android.vending') return true;
      var c = intent.getComponent();
      if (c !== null && c.getPackageName() === 'com.android.vending') return true;
    } catch (e) {}
    return false;
  }

  // 1. Swallow redirects to the Play Store (every startActivity overload on both
  //    Activity and ContextWrapper - covers Activity/Application/Service callers).
  ['android.app.Activity', 'android.content.ContextWrapper'].forEach(function (cn) {
    try {
      var C = Java.use(cn);
      C.startActivity.overloads.forEach(function (ov) {
        ov.implementation = function () {
          if (arguments.length > 0 && arguments[0] !== null && isPlayIntent(arguments[0])) {
            log('blocked Play-Store redirect (' + cn + '.startActivity)');
            return;
          }
          return ov.apply(this, arguments);
        };
      });
    } catch (e) {}
  });
  try {
    var Act = Java.use('android.app.Activity');
    Act.startActivityForResult.overloads.forEach(function (ov) {
      ov.implementation = function () {
        if (arguments.length > 0 && arguments[0] !== null && isPlayIntent(arguments[0])) {
          log('blocked Play-Store redirect (startActivityForResult)');
          return;
        }
        return ov.apply(this, arguments);
      };
    });
  } catch (e) {}

  // 2. Stop the app killing itself after a failed check.
  try { var S = Java.use('java.lang.System'); S.exit.implementation = function (c) { log('blocked System.exit(' + c + ')'); }; } catch (e) {}
  try { var P = Java.use('android.os.Process'); P.killProcess.implementation = function (p) { log('blocked Process.killProcess(' + p + ')'); }; } catch (e) {}
  try { var R = Java.use('java.lang.Runtime'); R.exit.implementation = function (c) { log('blocked Runtime.exit(' + c + ')'); }; R.halt.implementation = function (c) { log('blocked Runtime.halt(' + c + ')'); }; } catch (e) {}

  // 3. Signature self-check spoof. The app's ORIGINAL signing cert (base64 DER)
  //    is baked in at patch time; if it couldn't be extracted the token is empty
  //    and this whole block is a no-op. Makes PackageManager report the ORIGINAL
  //    cert so apps comparing their runtime signature to a hardcoded value pass.
  var ORIGINAL_CERT_B64 = '__CERT_B64__';
  if (ORIGINAL_CERT_B64.length > 0) {
    try {
      var Signature = Java.use('android.content.pm.Signature');
      var B64 = Java.use('android.util.Base64');
      var SIG = 'android.content.pm.Signature';
      var makeSig = function () { return Signature.$new(B64.decode(ORIGINAL_CERT_B64, 0)); };
      var spoofInfo = function (info) {
        try { if (info.signatures.value !== null) info.signatures.value = Java.array(SIG, [makeSig()]); } catch (e) {}
        return info;
      };
      var APM = Java.use('android.app.ApplicationPackageManager');
      // GET_SIGNATURES path (legacy).
      try {
        APM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (p, f) {
          return spoofInfo(this.getPackageInfo(p, f));
        };
      } catch (e) {}
      // API 33+ PackageInfoFlags overload.
      try {
        APM.getPackageInfo.overload('java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags').implementation = function (p, f) {
          return spoofInfo(this.getPackageInfo(p, f));
        };
      } catch (e) {}
      // GET_SIGNING_CERTIFICATES path (API 28+).
      var SI = Java.use('android.content.pm.SigningInfo');
      try { SI.getApkContentsSigners.implementation = function () { return Java.array(SIG, [makeSig()]); }; } catch (e) {}
      try { SI.getSigningCertificateHistory.implementation = function () { return Java.array(SIG, [makeSig()]); }; } catch (e) {}
      try { SI.hasMultipleSigners.implementation = function () { return false; }; } catch (e) {}
      log('signature spoof active (original cert restored)');
    } catch (e) { log('signature spoof failed: ' + e); }
  }

  log('bypass installed (Play-redirect + self-kill + signature spoof)');

  // --- Further app-specific hooks (edit as needed) ---------------------------
  // OkHttp CertificatePinner:
  //   Java.use('okhttp3.CertificatePinner').check.overload(
  //     'java.lang.String', 'java.util.List').implementation = function () {};
  // Play Integrity / SafetyNet: hook the app's verdict handler to force a genuine
  // result - class names are app- and version-specific.
});
"#;

fn inject_frida(
    decode_dir: &Path,
    gadget_path: &str,
    abi_pref: &str,
    script_mode: bool,
    script_path: &str,
    src_apk: &Path,
) -> Result<Vec<String>, String> {
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
        if !KNOWN_ABIS.contains(&abi_pref) {
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

    // 2b. Script mode: bundle a Frida script + gadget config next to the gadget so
    //     the script auto-runs on launch — no PC-side `frida` attach. Both files
    //     MUST end in `.so`: Android's installer only extracts `*.so` entries from
    //     lib/<abi>/ into the app's native-lib dir, and the gadget reads its config
    //     from that real directory. The gadget looks for `<its-name>.config.so`
    //     (libfrida-gadget.config.so); the config points at the script by a path
    //     relative to that dir. Relies on the libs being on a real filesystem —
    //     guaranteed by the android:extractNativeLibs="true" forced in run_patch.
    if script_mode {
        let mut script = if script_path.trim().is_empty() {
            DEFAULT_FRIDA_BYPASS.to_string()
        } else {
            std::fs::read_to_string(script_path)
                .map_err(|e| format!("read Frida script '{script_path}': {e}"))?
        };
        // Bake the app's ORIGINAL signing certificate into the script (if it uses
        // the `__CERT_B64__` token) so it can spoof signature self-checks. Read
        // from the *source* APK before we re-sign it. Best-effort: on failure the
        // token becomes empty and the script's signature-spoof block no-ops.
        if script.contains("__CERT_B64__") {
            match original_signing_cert_b64(src_apk) {
                Ok(b64) => {
                    script = script.replace("__CERT_B64__", &b64);
                    notes.push(
                        "Baked the app's original signing certificate into the Frida script — it \
                         spoofs PackageManager signature / SigningInfo lookups so self-signature \
                         checks see the original cert."
                            .to_string(),
                    );
                }
                Err(e) => {
                    script = script.replace("__CERT_B64__", "");
                    notes.push(format!(
                        "Could not read the original signing cert ({e}); signature-spoof left off \
                         (Play-redirect + self-kill hooks still active)."
                    ));
                }
            }
        }
        std::fs::write(abi_dir.join("libfrida-gadget.script.so"), script)
            .map_err(|e| format!("write Frida script: {e}"))?;
        // Gadget config: run the bundled script (path resolved relative to this dir).
        let config = "{\n  \"interaction\": {\n    \"type\": \"script\",\n    \"path\": \"./libfrida-gadget.script.so\",\n    \"on_change\": \"reload\"\n  }\n}\n";
        std::fs::write(abi_dir.join("libfrida-gadget.config.so"), config)
            .map_err(|e| format!("write Frida config: {e}"))?;
    }

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

    notes.push(format!("Frida gadget injected into {launcher} (lib/{abi})."));
    if script_mode {
        notes.push(if script_path.trim().is_empty() {
            "Frida script mode: bundled the built-in generic bypass — it auto-runs on \
             launch (no PC attach) and blocks Play-Store redirects and app self-kills. \
             Supply a custom .js for app-specific cert pinning / integrity checks."
                .to_string()
        } else {
            format!("Frida script mode: bundled '{script_path}' — auto-runs on launch, no PC attach.")
        });
    } else {
        notes.push(
            "Frida gadget in listen mode: launch the app (it blocks on startup), then attach \
             from a PC with `frida -U Gadget -l yourscript.js`. Turn on script mode to bundle \
             a self-running script instead."
                .to_string(),
        );
    }
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

// ─── Original signing-certificate extraction (for the Frida signature spoof) ───
// Reads the source APK's signing certificate so the bundled Frida script can make
// PackageManager report the ORIGINAL cert — defeating self-signature checks that
// our debug re-sign would otherwise trip. Prefer the v2/v3 APK Signing Block
// (modern apps, no external tool); fall back to keytool for a v1 (JAR) signature.

/// Standard base64 (single line) of the app's first signing certificate (DER).
fn original_signing_cert_b64(apk: &Path) -> Result<String, String> {
    if let Ok(bytes) = std::fs::read(apk) {
        if let Some(der) = v2v3_first_cert_der(&bytes) {
            use base64::Engine;
            return Ok(base64::engine::general_purpose::STANDARD.encode(der));
        }
    }
    // v1-only APK (no signing block): ask keytool for the JAR signer cert (PEM).
    v1_cert_b64(apk)
        .ok_or_else(|| "no v2/v3 signing block and keytool returned no v1 certificate".to_string())
}

/// Base64 body of the v1 (JAR) signing cert via `keytool -printcert -rfc`, or None.
fn v1_cert_b64(apk: &Path) -> Option<String> {
    let out = run(
        Command::new("keytool")
            .args(["-printcert", "-rfc", "-jarfile"])
            .arg(apk),
        "keytool printcert",
    )
    .ok()?;
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let b = out.find(begin)? + begin.len();
    let e = out[b..].find(end)? + b;
    let body: String = out[b..e].split_whitespace().collect();
    (!body.is_empty()).then_some(body)
}

// ── APK Signing Block (v2/v3) reader ─────────────────────────────────────────
// Walks only the length fields to pull the first signer's raw X.509 cert (DER);
// it does not parse the certificate itself. All integers are little-endian.

fn le_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_u64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}
/// Read a u32-length-prefixed slice at `o`; return (slice, offset just past it).
fn read_lp32(b: &[u8], o: usize) -> Option<(&[u8], usize)> {
    let n = le_u32(b, o)? as usize;
    let start = o + 4;
    let end = start.checked_add(n)?;
    Some((b.get(start..end)?, end))
}
/// Read a u32-length-prefixed slice at `o`.
fn lp32(b: &[u8], o: usize) -> Option<&[u8]> {
    read_lp32(b, o).map(|(s, _)| s)
}

/// Central-directory start offset from the ZIP End-of-Central-Directory record.
fn zip_cd_offset(b: &[u8]) -> Option<usize> {
    const SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    let last = b.len().checked_sub(22)?;
    let min = b.len().saturating_sub(65_557); // 22 + max comment 65535
    let mut i = last;
    loop {
        if b[i..i + 4] == SIG {
            return le_u32(b, i + 16).map(|v| v as usize);
        }
        if i == min {
            return None;
        }
        i -= 1;
    }
}

/// First signer's certificate (DER) from a v2/v3 APK Signing Block, if present.
fn v2v3_first_cert_der(b: &[u8]) -> Option<Vec<u8>> {
    let cd = zip_cd_offset(b)?;
    if cd < 24 || cd > b.len() {
        return None;
    }
    let magic = b.get(cd - 16..cd)?;
    if magic != b"APK Sig Block 42" {
        return None;
    }
    let block_size = le_u64(b, cd - 24)? as usize;
    let block_start = cd.checked_sub(8 + block_size)?;
    if le_u64(b, block_start)? as usize != block_size {
        return None;
    }
    // ID-value pairs live between the leading size field and the trailing size.
    let pairs = b.get(block_start + 8..cd - 24)?;
    let mut i = 0usize;
    let mut v3: Option<Vec<u8>> = None;
    while i + 8 <= pairs.len() {
        let plen = le_u64(pairs, i)? as usize;
        if plen < 4 {
            break;
        }
        let start = i + 8;
        let end = start.checked_add(plen)?;
        if end > pairs.len() {
            break;
        }
        let id = le_u32(pairs, start)?;
        let value = &pairs[start + 4..end];
        if id == 0x7109_871a {
            return signer_seq_first_cert(value); // v2 — preferred
        } else if id == 0xf053_68c0 && v3.is_none() {
            v3 = signer_seq_first_cert(value); // v3 — fallback
        }
        i = end;
    }
    v3
}

/// `value` = u32-len-prefixed signers; dig to the first signer's first cert.
/// Signed-data begins with a digests sequence, then the certificates sequence
/// (same placement in v2 and v3), so skip digests and read certificate #0.
fn signer_seq_first_cert(value: &[u8]) -> Option<Vec<u8>> {
    let signers = lp32(value, 0)?;
    let signer = lp32(signers, 0)?;
    let signed_data = lp32(signer, 0)?;
    let (_digests, after) = read_lp32(signed_data, 0)?;
    let certs = lp32(signed_data, after)?;
    let cert = lp32(certs, 0)?;
    Some(cert.to_vec())
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
        no_window(&mut c);
        c
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new(bin)
    }
}

/// Windows: suppress the console window that would otherwise flash every time we
/// spawn a child console process (adb, curl, cmd, powershell). No-op elsewhere.
/// Every external command MUST go through this — the Add-Device dialog polls
/// `adb devices` every 2s, so an unflagged spawn shows a cmd-window loop once
/// adb resolves. Prefer this over duplicating the flag at each call site.
fn no_window(cmd: &mut Command) -> &mut Command {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Run a command, returning stdout on success or a stderr-derived error.
/// All arguments are passed as an argv array (no shell), so device serials and
/// package names cannot inject extra commands.
fn run(cmd: &mut Command, ctx: &str) -> Result<String, String> {
    let out = no_window(cmd)
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
