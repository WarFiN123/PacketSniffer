// ─── OS Certificate Store Integration ────────────────────────────────────────
// Platform-specific logic to check if the CA cert is in the OS trust store
// and install it if not. Compares by SHA1 thumbprint to detect stale certs
// from previous key generations.

use crate::proxy::ca::CertificateAuthority;
use std::path::PathBuf;

/// Ensure the CA certificate is trusted by the OS.
/// Returns a status message.
pub async fn ensure_ca_trusted() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let ca =
        CertificateAuthority::initialize(None).map_err(|e| format!("CA init failed: {}", e))?;
    let cert_path = ca.ca_cert_path();

    #[cfg(target_os = "windows")]
    return ensure_trusted_windows(&cert_path).await;

    #[cfg(target_os = "macos")]
    return ensure_trusted_macos(&cert_path).await;

    #[cfg(target_os = "linux")]
    return ensure_trusted_linux(&cert_path).await;

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    return Ok(format!(
        "Manual CA installation required. Certificate at: {}",
        cert_path.display()
    ));
}

/// Check if the CA is currently trusted by the OS without attempting to install it.
pub async fn check_ca_trusted() -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let ca =
        CertificateAuthority::initialize(None).map_err(|e| format!("CA init failed: {}", e))?;
    let _cert_path = ca.ca_cert_path();

    #[cfg(target_os = "windows")]
    {
        let cert_path_str = _cert_path.to_string_lossy().to_string();
        let file_thumbprint = get_cert_file_thumbprint(&cert_path_str)?;
        let store_thumbprint = get_store_thumbprint();
        if let Some(stored) = store_thumbprint {
            return Ok(stored.eq_ignore_ascii_case(&file_thumbprint));
        }
        return Ok(false);
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let check = Command::new("security")
            .args(["find-certificate", "-c", "PacketSniffer Root CA"])
            .output()?;
        return Ok(check.status.success());
    }

    #[cfg(target_os = "linux")]
    {
        let dest = "/usr/local/share/ca-certificates/packetsniffer-ca.crt";
        return Ok(std::path::Path::new(dest).exists());
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    return Ok(true); // Assume yes on unknown OS to avoid popups
}

// ─── Windows ──────────────────────────────────────────────────────────────────

/// Windows: compare thumbprint of installed cert vs cert file.
/// If mismatched or missing, remove stale cert and install current one.
/// Uses certutil with UAC elevation via powershell RunAs.
#[cfg(target_os = "windows")]
async fn ensure_trusted_windows(
    cert_path: &PathBuf,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let cert_path_str = cert_path.to_string_lossy().to_string();

    // Get the SHA1 thumbprint of the cert FILE we want installed
    let file_thumbprint = get_cert_file_thumbprint(&cert_path_str)?;
    log::info!("CA cert file thumbprint: {}", file_thumbprint);

    // Check what's currently in the Local Machine Root store
    let store_thumbprint = get_store_thumbprint();

    match store_thumbprint {
        Some(ref stored) if stored.eq_ignore_ascii_case(&file_thumbprint) => {
            // Exact match — nothing to do for OS store
            // But still ensure Firefox is configured
            configure_firefox_enterprise_roots();
            return Ok("CA certificate is already trusted (thumbprint matches)".to_string());
        }
        Some(ref stored) => {
            // Stale cert from a previous key generation — remove it first
            log::info!(
                "Stale CA in store (thumbprint {}), replacing with {}",
                stored,
                file_thumbprint
            );
            let _ = run_elevated(&format!("certutil -delstore Root {}", stored));
        }
        None => {
            log::info!("No existing CA cert in store, installing");
        }
    }

    // Install current cert into Local Machine Root store (requires elevation)
    let result = run_elevated(&format!("certutil -addstore Root \"{}\"", cert_path_str));

    match result {
        Ok(()) => {
            log::info!("CA certificate installed into Root store");
            // Also configure Firefox to trust the OS root store
            configure_firefox_enterprise_roots();
            Ok("CA certificate installed successfully".to_string())
        }
        Err(e) => Err(format!(
            "Failed to install CA certificate ({}). You can install manually:\n  \
                 certutil -addstore Root \"{}\"",
            e, cert_path_str
        )
        .into()),
    }
}

/// Get the SHA1 thumbprint of a cert file using certutil -hashfile.
#[cfg(target_os = "windows")]
fn get_cert_file_thumbprint(
    cert_path: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // certutil -dump shows the cert hash for PEM files
    let output = Command::new("certutil")
        .args(["-dump", cert_path])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;

    let text = String::from_utf8_lossy(&output.stdout);

    // Look for "Cert Hash(sha1): ..." in the dump output
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Cert Hash(sha1):") {
            let hash = trimmed
                .trim_start_matches("Cert Hash(sha1):")
                .trim()
                .replace(' ', "");
            return Ok(hash);
        }
    }

    Err("Could not determine cert file thumbprint".into())
}

/// Get the SHA1 thumbprint of our CA cert in the Local Machine Root store.
/// Returns None if not found.
#[cfg(target_os = "windows")]
fn get_store_thumbprint() -> Option<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let output = Command::new("certutil")
        .args(["-store", "Root", "PacketSniffer Root CA"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Cert Hash(sha1):") {
            let hash = trimmed
                .trim_start_matches("Cert Hash(sha1):")
                .trim()
                .replace(' ', "");
            return Some(hash);
        }
    }

    None
}

/// Run a command with UAC elevation via powershell Start-Process -Verb RunAs.
#[cfg(target_os = "windows")]
fn run_elevated(command: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Split into program and arguments for Start-Process
    // We use cmd /c so we can pass the full command string
    let status = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Start-Process cmd -ArgumentList '/c','{}' -Verb RunAs -Wait -WindowStyle Hidden",
                command.replace('\'', "''")
            ),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("Elevated command failed: {}", command).into())
    }
}

/// Configure Firefox to trust our CA certificate using multiple approaches:
///
/// 1. `policies.json` in Firefox's `distribution/` dir — most reliable, specifies
///    our CA cert file path directly. Firefox reads this on every startup.
/// 2. HKLM registry policy (`ImportEnterpriseRoots`) — tells Firefox to trust
///    the Windows Root CA store (where our cert is installed).
/// 3. Per-profile `user.js` (`security.enterprise_roots.enabled`) — same effect
///    as (2) but applied per-profile. Fallback if elevation fails.
#[cfg(target_os = "windows")]
fn configure_firefox_enterprise_roots() {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Get the CA cert path for policies.json
    let ca_cert_path = get_ca_cert_path();

    // ── Approach 1: policies.json ────────────────────────────────────────
    // Find Firefox installation directories and write distribution/policies.json
    if let Some(cert_path) = &ca_cert_path {
        install_firefox_policies_json(cert_path);
    }

    // ── Approach 2: Registry policy ─────────────────────────────────────
    let check = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\Certificates",
            "/v",
            "ImportEnterpriseRoots",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let registry_already_set = if let Ok(output) = check {
        String::from_utf8_lossy(&output.stdout).contains("0x1")
    } else {
        false
    };

    if registry_already_set {
        log::debug!("Firefox ImportEnterpriseRoots already enabled");
    } else {
        let result = run_elevated(
            r#"reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox\Certificates" /v ImportEnterpriseRoots /t REG_DWORD /d 1 /f"#,
        );

        match result {
            Ok(()) => {
                log::info!("Firefox ImportEnterpriseRoots policy set (HKLM)");
                log::info!("Firefox configured to trust OS root store via registry policy");
            }
            Err(e) => {
                log::warn!(
                    "Could not set Firefox HKLM policy ({}), trying per-profile fallback",
                    e
                );
                // Fallback: write user.js in each Firefox profile
                configure_firefox_profiles_fallback();
            }
        }
    }
}

/// Get the CA cert path from the CertificateAuthority data directory.
#[cfg(target_os = "windows")]
fn get_ca_cert_path() -> Option<String> {
    let ca = crate::proxy::ca::CertificateAuthority::initialize(None).ok()?;
    let path = ca.ca_cert_path();
    if path.exists() {
        Some(path.to_string_lossy().to_string())
    } else {
        None
    }
}

/// Write Firefox's `distribution/policies.json` to directly install our CA cert.
/// This is the most reliable approach — Firefox reads policies.json on startup
/// and installs the specified CA certs without any user interaction.
#[cfg(target_os = "windows")]
fn install_firefox_policies_json(ca_cert_path: &str) {
    // Common Firefox install locations on Windows
    let program_files = std::env::var("ProgramFiles").unwrap_or_default();
    let program_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_default();

    let mut firefox_dirs = Vec::new();
    if !program_files.is_empty() {
        firefox_dirs.push(std::path::PathBuf::from(&program_files).join("Mozilla Firefox"));
    }
    if !program_files_x86.is_empty() {
        firefox_dirs.push(std::path::PathBuf::from(&program_files_x86).join("Mozilla Firefox"));
    }

    // Also try to find Firefox from the registry
    if let Some(path) = find_firefox_from_registry() {
        let parent = std::path::Path::new(&path)
            .parent()
            .map(|p| p.to_path_buf());
        if let Some(dir) = parent {
            if !firefox_dirs.iter().any(|d| d == &dir) {
                firefox_dirs.push(dir);
            }
        }
    }

    // Normalize cert path: use forward slashes for JSON (JSON needs escaped backslashes)
    let cert_path_json = ca_cert_path.replace('\\', "\\\\");

    let policies_content = format!(
        r#"{{
  "policies": {{
    "Certificates": {{
      "ImportEnterpriseRoots": true,
      "Install": [
        "{}"
      ]
    }}
  }}
}}"#,
        cert_path_json
    );

    for firefox_dir in &firefox_dirs {
        if !firefox_dir.exists() {
            continue;
        }

        let dist_dir = firefox_dir.join("distribution");
        let policies_file = dist_dir.join("policies.json");

        // Write new policies.json (requires admin since Program Files is protected)
        // We overwrite to ensure it points to the correct PacketSniffer cert
        match write_policies_elevated(&policies_file, &policies_content) {
            Ok(()) => {
                log::info!("Wrote Firefox policies.json to {}", policies_file.display());
                log::info!(
                    "Firefox policies.json installed at {}",
                    policies_file.display()
                );
            }
            Err(e) => {
                log::warn!(
                    "Failed to write policies.json to {}: {}",
                    policies_file.display(),
                    e
                );
            }
        }
    }
}

/// Write policies.json using elevated permissions (Program Files is admin-protected).
#[cfg(target_os = "windows")]
fn write_policies_elevated(
    policies_path: &std::path::Path,
    content: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Ensure the distribution directory exists
    if let Some(parent) = policies_path.parent() {
        if !parent.exists() {
            let mkdir_cmd = format!("mkdir \"{}\"", parent.to_string_lossy());
            let _ = run_elevated(&mkdir_cmd);
        }
    }

    // Write via elevated cmd — use echo with a temp file approach
    // (cmd echo doesn't handle multiline well, so use PowerShell Set-Content)
    let escaped_content = content.replace('"', "\\\"");
    let ps_cmd = format!(
        "powershell -Command \"Set-Content -Path '{}' -Value '{}' -Encoding UTF8\"",
        policies_path.to_string_lossy(),
        escaped_content.replace('\'', "''")
    );

    run_elevated(&ps_cmd)
}

/// Try to find Firefox installation path from the registry.
#[cfg(target_os = "windows")]
fn find_firefox_from_registry() -> Option<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
            "/ve",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.contains("REG_SZ") {
            // Extract the path after REG_SZ
            let parts: Vec<&str> = trimmed.splitn(3, "REG_SZ").collect();
            if parts.len() >= 2 {
                return Some(parts[1].trim().to_string());
            }
        }
    }
    None
}

/// Fallback: set security.enterprise_roots.enabled in user.js for each Firefox profile.
/// Does not require elevation.
#[cfg(target_os = "windows")]
fn configure_firefox_profiles_fallback() {
    let appdata = match std::env::var("APPDATA") {
        Ok(v) => v,
        Err(_) => return,
    };

    let profiles_dir = std::path::Path::new(&appdata)
        .join("Mozilla")
        .join("Firefox")
        .join("Profiles");
    if !profiles_dir.exists() {
        log::debug!("No Firefox profiles found at {}", profiles_dir.display());
        return;
    }

    let entries = match std::fs::read_dir(&profiles_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let pref_line = r#"user_pref("security.enterprise_roots.enabled", true);"#;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let user_js = path.join("user.js");

        // Check if already set
        if user_js.exists() {
            if let Ok(contents) = std::fs::read_to_string(&user_js) {
                if contents.contains("security.enterprise_roots.enabled") {
                    continue; // Already configured
                }
            }
        }

        // Append the preference
        let mut content = if user_js.exists() {
            std::fs::read_to_string(&user_js).unwrap_or_default()
        } else {
            String::new()
        };

        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(pref_line);
        content.push('\n');

        match std::fs::write(&user_js, &content) {
            Ok(()) => {
                log::info!("Wrote enterprise_roots pref to {}", user_js.display());
            }
            Err(e) => {
                log::warn!("Failed to write {}: {}", user_js.display(), e);
            }
        }
    }
}

// ─── macOS ────────────────────────────────────────────────────────────────────

/// macOS: use security add-trusted-cert with admin privileges.
#[cfg(target_os = "macos")]
async fn ensure_trusted_macos(
    cert_path: &PathBuf,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    let cert_path_str = cert_path.to_string_lossy().to_string();

    // Check if already in keychain
    let check = Command::new("security")
        .args(["find-certificate", "-c", "PacketSniffer Root CA"])
        .output();

    if let Ok(output) = check {
        if output.status.success() {
            return Ok("CA certificate is already trusted".to_string());
        }
    }

    // Install with admin prompt
    let status = Command::new("osascript")
        .args([
            "-e",
            &format!(
                "do shell script \"security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '{}'\" with administrator privileges",
                cert_path_str
            ),
        ])
        .status()?;

    if status.success() {
        Ok("CA certificate installed successfully".to_string())
    } else {
        Err("Failed to install CA certificate. Please install manually.".into())
    }
}

// ─── Linux ────────────────────────────────────────────────────────────────────

/// Linux: copy to /usr/local/share/ca-certificates/ and run update-ca-certificates.
#[cfg(target_os = "linux")]
async fn ensure_trusted_linux(
    cert_path: &PathBuf,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    let dest = "/usr/local/share/ca-certificates/packetsniffer-ca.crt";
    let cert_path_str = cert_path.to_string_lossy().to_string();

    // Try to install the cert into the OS store
    let mut needs_install = true;
    if let Ok(installed_content) = std::fs::read_to_string(dest) {
        if let Ok(current_content) = std::fs::read_to_string(cert_path) {
            if installed_content == current_content {
                needs_install = false;
            }
        }
    }

    let os_store_success = if needs_install {
        let status = Command::new("pkexec")
            .args([
                "bash",
                "-c",
                &format!(
                    "cp '{}' '{}' && update-ca-certificates",
                    cert_path_str, dest
                ),
            ])
            .status()?;
        status.success()
    } else {
        true
    };

    // Configure Firefox Enterprise policies and profiles for Linux
    configure_firefox_enterprise_roots_linux(&cert_path_str);

    if os_store_success {
        Ok("CA certificate installed successfully".to_string())
    } else {
        Err(format!(
            "Failed to install CA certificate. Please manually copy {} to {} and run update-ca-certificates",
            cert_path_str, dest
        ).into())
    }
}

/// Configure Firefox to trust our CA certificate on Linux.
/// Writes to /etc/firefox/policies/policies.json and sets up user.js profiles
#[cfg(target_os = "linux")]
fn configure_firefox_enterprise_roots_linux(ca_cert_path: &str) {
    use std::process::Command;

    // 1. Install system-wide policy using pkexec
    let policy_dirs = [
        "/etc/firefox/policies",
        "/usr/lib/firefox/distribution",
        "/usr/lib/firefox-addons/distribution",
    ];

    // Read the PEM and convert to pure base64 for Firefox policy (bypasses Snap filesystem restrictions)
    let cert_content = std::fs::read_to_string(ca_cert_path).unwrap_or_default();
    let cert_base64 = if cert_content.contains("BEGIN CERTIFICATE") {
        cert_content
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>()
    } else {
        // Fallback to path if reading fails or not a standard PEM
        ca_cert_path.replace('\\', "\\\\").replace('"', "\\\"")
    };

    let policies_content = format!(
        r#"{{
  "policies": {{
    "Certificates": {{
      "ImportEnterpriseRoots": true,
      "Install": [
        "{}"
      ]
    }}
  }}
}}"#,
        cert_base64
    );

    let mut script = String::new();
    for dir in policy_dirs {
        script.push_str(&format!(
            "mkdir -p '{}' && echo '{}' > '{}/policies.json'; ",
            dir, policies_content, dir
        ));
    }

    let status = Command::new("pkexec")
        .args(["bash", "-c", &script])
        .status();

    if let Ok(s) = status {
        if s.success() {
            log::info!("Wrote Firefox policies.json (with base64 cert) to multiple system directories");
        } else {
            log::warn!("pkexec failed to write policies.json. Exit status: {}", s);
        }
    }

    // 2. Add cert to all NSS databases (cert9.db) using certutil as a fallback
    install_firefox_nss_linux(ca_cert_path);

    // 3. Fallback: Write user.js into all local Firefox profiles
    configure_firefox_profiles_fallback_linux();
}

/// Fallback for Linux: attempts to install the CA certificate directly into Firefox's
/// NSS database using `certutil` (from libnss3-tools).
#[cfg(target_os = "linux")]
fn install_firefox_nss_linux(ca_cert_path: &str) {
    use std::process::Command;

    // Check if certutil is installed
    if Command::new("certutil").arg("-H").output().is_err() {
        log::warn!("certutil not found. Please install libnss3-tools to automatically trust CA in Firefox via NSS.");
        return;
    }

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };

    let base_dirs = [
        format!("{}/.mozilla/firefox", home),
        format!("{}/snap/firefox/common/.mozilla/firefox", home),
        format!("{}/.var/app/org.mozilla.firefox/.mozilla/firefox", home),
    ];

    for base in base_dirs {
        let profiles_dir = std::path::Path::new(&base);
        if !profiles_dir.exists() {
            continue;
        }

        let entries = match std::fs::read_dir(profiles_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // A profile directory must have a cert9.db
            if !path.join("cert9.db").exists() {
                continue;
            }

            log::info!("Installing CA directly to NSS database in profile: {}", path.display());
            
            // certutil -d sql:/path/to/profile -A -t "C,," -n "PacketSniffer CA" -i /path/to/cert
            let status = Command::new("certutil")
                .args([
                    "-d",
                    &format!("sql:{}", path.display()),
                    "-A",
                    "-t",
                    "C,,",
                    "-n",
                    "PacketSniffer Root CA",
                    "-i",
                    ca_cert_path,
                ])
                .status();

            if let Ok(s) = status {
                if !s.success() {
                    log::warn!("certutil failed for profile {}", path.display());
                }
            } else {
                log::warn!("Failed to execute certutil for profile {}", path.display());
            }
        }
    }
}

/// Fallback for Linux: sets security.enterprise_roots.enabled in user.js for each Firefox profile.
#[cfg(target_os = "linux")]
fn configure_firefox_profiles_fallback_linux() {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };

    let base_dirs = [
        format!("{}/.mozilla/firefox", home),
        format!("{}/snap/firefox/common/.mozilla/firefox", home),
        format!("{}/.var/app/org.mozilla.firefox/.mozilla/firefox", home),
    ];

    let pref_line = r#"user_pref("security.enterprise_roots.enabled", true);"#;

    for base in base_dirs {
        let profiles_dir = std::path::Path::new(&base);
        if !profiles_dir.exists() {
            continue;
        }

        let entries = match std::fs::read_dir(profiles_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // A valid Firefox profile usually has a prefs.js or is ending with .default / .default-release
            let user_js = path.join("user.js");

            let mut content = if user_js.exists() {
                std::fs::read_to_string(&user_js).unwrap_or_default()
            } else {
                String::new()
            };

            if content.contains("security.enterprise_roots.enabled") {
                continue; // Already configured
            }

            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(pref_line);
            content.push('\n');

            match std::fs::write(&user_js, &content) {
                Ok(()) => {
                    log::info!("Wrote enterprise_roots pref to {}", user_js.display());
                }
                Err(e) => {
                    log::warn!("Failed to write {}: {}", user_js.display(), e);
                }
            }
        }
    }
}
