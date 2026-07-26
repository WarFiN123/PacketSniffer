// ─── OS Certificate Store Integration ────────────────────────────────────────
// Checks whether the root CA is trusted and installs it if not.
//
// Windows / macOS: putting the CA in the OS trust store is enough. Firefox
// mirrors that store when `security.enterprise_roots.enabled` is on, which we
// turn on via an enterprise policy.
//
// Linux: there is no such bridge. `security.enterprise_roots.enabled` is
// implemented only for Windows and macOS, so a CA sitting in /etc/ssl is
// invisible to Firefox — every HTTPS page then fails with
// MOZILLA_PKIX_ERROR_MITM_DETECTED. That error is just Firefox's rename of
// SEC_ERROR_UNKNOWN_ISSUER: its MITM canary probe comes back signed by the same
// unknown root, so it concludes a proxy is intercepting. The cure is to put the
// CA where Firefox actually looks — each profile's own NSS database, plus an
// enterprise policy so profiles created later pick it up too.

use crate::proxy::ca::CertificateAuthority;
use serde::Serialize;
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Nickname the CA is filed under in NSS databases and OS trust stores.
const CA_NICKNAME: &str = "PacketSniffer Root CA";

/// Outcome of an install attempt, rendered by the CA dialog.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaInstallResult {
    /// Headline result, shown as the dialog body.
    pub message: String,
    /// Absolute path to the CA PEM so the user can install it by hand.
    pub cert_path: String,
    /// Non-fatal problems worth surfacing (a store we couldn't reach, a missing
    /// tool). Install can succeed for one browser and fail for another.
    pub warnings: Vec<String>,
    /// Browsers read trust anchors at startup, so a restart is usually needed.
    pub needs_browser_restart: bool,
}

/// Returns a list of package names that are missing and needed for full functionality.
pub fn check_missing_dependencies() -> Vec<String> {
    #[allow(unused_mut)]
    let mut missing = Vec::new();

    #[cfg(target_os = "linux")]
    if !has_certutil() {
        missing.push("libnss3-tools".to_string());
    }

    missing
}

/// Attempt to install a system package by name. Returns Ok on success.
#[cfg(target_os = "linux")]
pub fn install_package(package: &str) -> Result<String, BoxErr> {
    use std::process::Command;

    // Try apt (Debian/Ubuntu), then dnf (Fedora), then pacman (Arch), then zypper (SUSE).
    let managers: &[(&str, &[&str])] = &[
        ("apt-get", &["install", "-y", package]),
        ("dnf", &["install", "-y", package]),
        ("pacman", &["-S", "--noconfirm", package]),
        ("zypper", &["install", "-y", package]),
    ];

    for (mgr, args) in managers {
        if !has_command(mgr) {
            continue;
        }
        let output = Command::new("pkexec").arg(mgr).args(*args).output()?;
        if output.status.success() {
            return Ok(format!("{} installed successfully", package));
        }
        // The package manager's own diagnostics are far more useful than the
        // exit code alone ("package not found", "could not get lock", ...).
        let detail = first_meaningful_line(&output.stderr)
            .or_else(|| first_meaningful_line(&output.stdout))
            .unwrap_or_else(|| pkexec_hint(output.status.code()));
        return Err(format!("{} install failed: {}", package, detail).into());
    }

    Err("No supported package manager found (apt-get, dnf, pacman, or zypper)".into())
}

#[cfg(not(target_os = "linux"))]
pub fn install_package(_package: &str) -> Result<String, BoxErr> {
    Ok("No packages to install on this platform".to_string())
}

/// Ensure the CA certificate is trusted, installing it if necessary.
///
/// Runs on a blocking thread: every platform shells out to a privilege prompt
/// (UAC / osascript / pkexec) that can sit open for as long as the user takes,
/// and blocking an async runtime worker for that would stall the whole app.
pub async fn ensure_ca_trusted() -> Result<CaInstallResult, BoxErr> {
    tokio::task::spawn_blocking(ensure_ca_trusted_blocking).await?
}

fn ensure_ca_trusted_blocking() -> Result<CaInstallResult, BoxErr> {
    let ca = CertificateAuthority::initialize(None).map_err(|e| format!("CA init failed: {}", e))?;
    let cert_path = ca.ca_cert_path();

    #[cfg(target_os = "windows")]
    return ensure_trusted_windows(&cert_path);

    #[cfg(target_os = "macos")]
    return ensure_trusted_macos(&cert_path);

    #[cfg(target_os = "linux")]
    return ensure_trusted_linux(&cert_path);

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    Ok(CaInstallResult {
        message: "Manual CA installation is required on this platform.".to_string(),
        cert_path: cert_path.to_string_lossy().to_string(),
        warnings: Vec::new(),
        needs_browser_restart: true,
    })
}

/// Check whether the CA is currently trusted, without attempting to install it.
pub async fn check_ca_trusted() -> Result<bool, BoxErr> {
    tokio::task::spawn_blocking(check_ca_trusted_blocking).await?
}

fn check_ca_trusted_blocking() -> Result<bool, BoxErr> {
    let ca = CertificateAuthority::initialize(None).map_err(|e| format!("CA init failed: {}", e))?;
    let _cert_path = ca.ca_cert_path();

    #[cfg(target_os = "windows")]
    {
        let cert_path_str = _cert_path.to_string_lossy().to_string();
        let file_thumbprint = get_cert_file_thumbprint(&cert_path_str)?;
        return Ok(get_store_thumbprint()
            .is_some_and(|stored| stored.eq_ignore_ascii_case(&file_thumbprint)));
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let check = Command::new("security")
            .args([
                "find-certificate",
                "-c",
                CA_NICKNAME,
                "/Library/Keychains/System.keychain",
            ])
            .output()?;
        return Ok(check.status.success());
    }

    #[cfg(target_os = "linux")]
    return check_ca_trusted_linux(&_cert_path);

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    return Ok(true); // Assume yes on unknown OS to avoid popups
}

// ─── Windows ──────────────────────────────────────────────────────────────────

/// Windows: compare thumbprint of installed cert vs cert file.
/// If mismatched or missing, remove stale cert and install current one.
/// Uses certutil with UAC elevation via powershell RunAs.
#[cfg(target_os = "windows")]
fn ensure_trusted_windows(cert_path: &PathBuf) -> Result<CaInstallResult, BoxErr> {
    let cert_path_str = cert_path.to_string_lossy().to_string();

    // Get the SHA1 thumbprint of the cert FILE we want installed
    let file_thumbprint = get_cert_file_thumbprint(&cert_path_str)?;
    log::info!("CA cert file thumbprint: {}", file_thumbprint);

    // Check what's currently in the Local Machine Root store
    let store_thumbprint = get_store_thumbprint();

    match store_thumbprint {
        Some(ref stored) if stored.eq_ignore_ascii_case(&file_thumbprint) => {
            // Exact match — nothing to do for the OS store, but Firefox still
            // needs its policy pointing at the store.
            let warnings = configure_firefox_enterprise_roots();
            return Ok(CaInstallResult {
                message: "The CA certificate is already trusted by Windows.".to_string(),
                cert_path: cert_path_str,
                warnings,
                needs_browser_restart: false,
            });
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
    run_elevated(&format!("certutil -addstore Root \"{}\"", cert_path_str)).map_err(|e| {
        format!(
            "Failed to install the CA certificate ({}). To install it by hand, run as \
             administrator:\n  certutil -addstore Root \"{}\"",
            e, cert_path_str
        )
    })?;

    log::info!("CA certificate installed into Root store");
    let warnings = configure_firefox_enterprise_roots();

    Ok(CaInstallResult {
        message: "CA certificate installed into the Windows Root store.".to_string(),
        cert_path: cert_path_str,
        warnings,
        needs_browser_restart: true,
    })
}

/// Get the SHA1 thumbprint of a cert file using certutil.
/// Uses `certutil -dump` which reliably shows the cert hash for PEM files.
#[cfg(target_os = "windows")]
fn get_cert_file_thumbprint(cert_path: &str) -> Result<String, BoxErr> {
    let output = win_command("certutil", &["-dump", cert_path])?;

    if !output.status.success() {
        return Err(format!(
            "certutil -dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    parse_cert_hash(&String::from_utf8_lossy(&output.stdout))
        .filter(|h| h.len() == 40)
        .ok_or_else(|| format!("Could not find SHA1 hash in certutil output for {}", cert_path).into())
}

/// Get the SHA1 thumbprint of our CA cert in the Local Machine Root store.
/// Returns None if not found.
#[cfg(target_os = "windows")]
fn get_store_thumbprint() -> Option<String> {
    let output = win_command("certutil", &["-store", "Root", CA_NICKNAME]).ok()?;
    if !output.status.success() {
        return None;
    }
    parse_cert_hash(&String::from_utf8_lossy(&output.stdout))
}

/// Pull the `Cert Hash(sha1): ...` value out of certutil output.
#[cfg(target_os = "windows")]
fn parse_cert_hash(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("Cert Hash(sha1):"))
        .map(|hash| hash.trim().replace(' ', ""))
}

/// Run a console tool without flashing a window.
#[cfg(target_os = "windows")]
fn win_command(program: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

/// Run a command with UAC elevation via powershell Start-Process -Verb RunAs.
#[cfg(target_os = "windows")]
fn run_elevated(command: &str) -> Result<(), BoxErr> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
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
///
/// Returns any non-fatal problems for the UI.
#[cfg(target_os = "windows")]
fn configure_firefox_enterprise_roots() -> Vec<String> {
    let mut warnings = Vec::new();

    // ── Approach 1: policies.json ────────────────────────────────────────
    if let Some(cert_path) = get_ca_cert_path() {
        install_firefox_policies_json(&cert_path, &mut warnings);
    }

    // ── Approach 2: Registry policy ─────────────────────────────────────
    let registry_already_set = win_command(
        "reg",
        &[
            "query",
            r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\Certificates",
            "/v",
            "ImportEnterpriseRoots",
        ],
    )
    .map(|out| String::from_utf8_lossy(&out.stdout).contains("0x1"))
    .unwrap_or(false);

    if registry_already_set {
        log::debug!("Firefox ImportEnterpriseRoots already enabled");
        return warnings;
    }

    match run_elevated(
        r#"reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox\Certificates" /v ImportEnterpriseRoots /t REG_DWORD /d 1 /f"#,
    ) {
        Ok(()) => log::info!("Firefox configured to trust the OS root store (HKLM policy)"),
        Err(e) => {
            log::warn!(
                "Could not set Firefox HKLM policy ({}), falling back to per-profile prefs",
                e
            );
            configure_firefox_profiles_fallback();
        }
    }

    warnings
}

/// Get the CA cert path from the CertificateAuthority data directory.
#[cfg(target_os = "windows")]
fn get_ca_cert_path() -> Option<String> {
    let ca = CertificateAuthority::initialize(None).ok()?;
    let path = ca.ca_cert_path();
    path.exists()
        .then(|| path.to_string_lossy().to_string())
}

/// Write Firefox's `distribution/policies.json` to directly install our CA cert.
/// This is the most reliable approach — Firefox reads policies.json on startup
/// and installs the specified CA certs without any user interaction.
#[cfg(target_os = "windows")]
fn install_firefox_policies_json(ca_cert_path: &str, warnings: &mut Vec<String>) {
    let mut firefox_dirs: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(|var| std::env::var(var).ok())
        .filter(|v| !v.is_empty())
        .map(|v| PathBuf::from(v).join("Mozilla Firefox"))
        .collect();

    // Also try to find Firefox from the registry
    if let Some(dir) = find_firefox_from_registry()
        .and_then(|path| PathBuf::from(path).parent().map(|p| p.to_path_buf()))
    {
        if !firefox_dirs.contains(&dir) {
            firefox_dirs.push(dir);
        }
    }

    let policies_content = firefox_policies_json(ca_cert_path);

    for firefox_dir in firefox_dirs.iter().filter(|d| d.exists()) {
        let policies_file = firefox_dir.join("distribution").join("policies.json");

        // Skip the elevation prompt when the file is already what we want.
        if std::fs::read_to_string(&policies_file).is_ok_and(|c| c == policies_content) {
            continue;
        }

        // Program Files is admin-protected, so this needs elevation.
        match write_policies_elevated(&policies_file, &policies_content) {
            Ok(()) => log::info!("Wrote Firefox policies.json to {}", policies_file.display()),
            Err(e) => {
                log::warn!(
                    "Failed to write policies.json to {}: {}",
                    policies_file.display(),
                    e
                );
                warnings.push(format!(
                    "Could not write Firefox's policy file at {}. Firefox should still pick the \
                     CA up from the Windows root store after a restart.",
                    policies_file.display()
                ));
            }
        }
    }
}

/// Write policies.json using elevated permissions (Program Files is admin-protected).
/// Writes content to a temp file first, then copies via elevated cmd to avoid
/// escaping issues with nested shell invocations.
#[cfg(target_os = "windows")]
fn write_policies_elevated(policies_path: &std::path::Path, content: &str) -> Result<(), BoxErr> {
    // Ensure the distribution directory exists
    if let Some(parent) = policies_path.parent() {
        if !parent.exists() {
            let _ = run_elevated(&format!("mkdir \"{}\"", parent.to_string_lossy()));
        }
    }

    // Write to a temp file first (no elevation needed), then copy elevated
    let temp_file = std::env::temp_dir().join("packetsniffer_policies.json");
    std::fs::write(&temp_file, content)?;

    let result = run_elevated(&format!(
        "copy /Y \"{}\" \"{}\"",
        temp_file.to_string_lossy(),
        policies_path.to_string_lossy()
    ));

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_file);

    result
}

/// Try to find Firefox installation path from the registry.
#[cfg(target_os = "windows")]
fn find_firefox_from_registry() -> Option<String> {
    let output = win_command(
        "reg",
        &[
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
            "/ve",
        ],
    )
    .ok()?;

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.split("REG_SZ").nth(1))
        .map(|path| path.trim().to_string())
}

/// Fallback: set security.enterprise_roots.enabled in user.js for each Firefox profile.
/// Does not require elevation.
#[cfg(target_os = "windows")]
fn configure_firefox_profiles_fallback() {
    let Ok(appdata) = std::env::var("APPDATA") else {
        return;
    };

    let profiles_dir = PathBuf::from(appdata)
        .join("Mozilla")
        .join("Firefox")
        .join("Profiles");
    if !profiles_dir.exists() {
        log::debug!("No Firefox profiles found at {}", profiles_dir.display());
        return;
    }

    let Ok(entries) = std::fs::read_dir(&profiles_dir) else {
        return;
    };

    let pref_line = r#"user_pref("security.enterprise_roots.enabled", true);"#;

    for path in entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
        let user_js = path.join("user.js");

        let mut content = std::fs::read_to_string(&user_js).unwrap_or_default();
        if content.contains("security.enterprise_roots.enabled") {
            continue; // Already configured
        }

        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(pref_line);
        content.push('\n');

        match std::fs::write(&user_js, &content) {
            Ok(()) => log::info!("Wrote enterprise_roots pref to {}", user_js.display()),
            Err(e) => log::warn!("Failed to write {}: {}", user_js.display(), e),
        }
    }
}

// ─── macOS ────────────────────────────────────────────────────────────────────

/// macOS: use security add-trusted-cert with admin privileges.
#[cfg(target_os = "macos")]
fn ensure_trusted_macos(cert_path: &PathBuf) -> Result<CaInstallResult, BoxErr> {
    use std::process::Command;

    let cert_path_str = cert_path.to_string_lossy().to_string();

    // Check if already in the System keychain (the login keychain isn't enough —
    // roots must be in the System keychain to be trusted for TLS).
    let already_trusted = Command::new("security")
        .args([
            "find-certificate",
            "-c",
            CA_NICKNAME,
            "/Library/Keychains/System.keychain",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if already_trusted {
        return Ok(CaInstallResult {
            message: "The CA certificate is already trusted by macOS.".to_string(),
            cert_path: cert_path_str,
            warnings: Vec::new(),
            needs_browser_restart: false,
        });
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

    if !status.success() {
        return Err(format!(
            "Failed to install the CA certificate. To install it by hand, run:\n  \
             sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '{}'",
            cert_path_str
        )
        .into());
    }

    Ok(CaInstallResult {
        message: "CA certificate added to the System keychain.".to_string(),
        cert_path: cert_path_str,
        warnings: Vec::new(),
        needs_browser_restart: true,
    })
}

// ─── Linux ────────────────────────────────────────────────────────────────────

/// Where a distro keeps drop-in trust anchors and how it rebuilds the bundle.
/// Firefox reads none of this (see `install_nss_ca`), but curl, git, python and
/// most CLI tooling do.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct TrustStore {
    /// Drop-in directory for PEM anchors.
    anchor_dir: &'static str,
    /// Anchor file name — Debian's `update-ca-certificates` only reads `.crt`.
    file_name: &'static str,
    /// Command that rebuilds the CA bundle from the anchor directory.
    refresh: &'static str,
}

#[cfg(target_os = "linux")]
impl TrustStore {
    fn anchor_path(&self) -> PathBuf {
        PathBuf::from(self.anchor_dir).join(self.file_name)
    }
}

/// Pick the trust-store layout for this distro.
///
/// Detection is by directory rather than by distro name: openSUSE also ships
/// `update-ca-certificates` and Arch also has an `/etc/pki`, so the anchor
/// directory is the only reliable discriminator.
#[cfg(target_os = "linux")]
fn trust_store() -> TrustStore {
    const CANDIDATES: &[TrustStore] = &[
        // Debian / Ubuntu
        TrustStore {
            anchor_dir: "/usr/local/share/ca-certificates",
            file_name: "packetsniffer-ca.crt",
            refresh: "update-ca-certificates",
        },
        // Fedora / RHEL
        TrustStore {
            anchor_dir: "/etc/pki/ca-trust/source/anchors",
            file_name: "packetsniffer-ca.pem",
            refresh: "update-ca-trust extract",
        },
        // openSUSE
        TrustStore {
            anchor_dir: "/etc/pki/trust/anchors",
            file_name: "packetsniffer-ca.pem",
            refresh: "update-ca-certificates",
        },
        // Arch
        TrustStore {
            anchor_dir: "/etc/ca-certificates/trust-source/anchors",
            file_name: "packetsniffer-ca.crt",
            refresh: "trust extract-compat",
        },
    ];

    let refresh_available =
        |c: &&TrustStore| c.refresh.split(' ').next().is_some_and(has_command);

    CANDIDATES
        .iter()
        .find(|c| std::path::Path::new(c.anchor_dir).is_dir() && refresh_available(c))
        .or_else(|| CANDIDATES.iter().find(refresh_available))
        .copied()
        .unwrap_or(CANDIDATES[0])
}

/// Linux: install into the system trust store *and* into every NSS database we
/// can find, because Firefox and Chromium ignore the system store entirely.
#[cfg(target_os = "linux")]
fn ensure_trusted_linux(cert_path: &PathBuf) -> Result<CaInstallResult, BoxErr> {
    let cert_pem = std::fs::read_to_string(cert_path)?;
    let cert_path_str = cert_path.to_string_lossy().to_string();
    let mut warnings = Vec::new();

    // ── 1. System store + Firefox enterprise policy ─────────────────────
    // Both need root, so they share a single pkexec call: one password prompt
    // instead of one per file.
    let store = trust_store();
    let anchor = store.anchor_path();
    let policies = firefox_policy_targets(&anchor.to_string_lossy());

    let anchor_current = std::fs::read_to_string(&anchor).is_ok_and(|c| c == cert_pem);
    let policies_current = policies
        .iter()
        .all(|(path, want)| std::fs::read_to_string(path).is_ok_and(|c| &c == want));

    let mut system_store_ok = true;
    if anchor_current && policies_current {
        log::debug!("System trust store and Firefox policies are already up to date");
    } else if let Err(e) = run_pkexec(&root_install_script(&cert_pem, &store, &policies)) {
        system_store_ok = false;
        log::warn!("System-wide CA install failed: {}", e);
        warnings.push(format!(
            "Could not install into the system trust store ({e}). Browsers may still work via \
             their own certificate databases, but curl, git and other command-line tools will \
             not trust the proxy."
        ));
    }

    // ── 2. NSS databases — the part that actually fixes Firefox ─────────
    // Runs unprivileged: every database below lives under the user's own home.
    let databases = nss_databases();
    let mut nss_ok = 0usize;

    if !has_certutil() {
        warnings.push(
            "`certutil` is missing, so Firefox's own certificate database could not be updated. \
             Install libnss3-tools (or nss-tools) and run this again — without it Firefox will \
             keep reporting MOZILLA_PKIX_ERROR_MITM_DETECTED."
                .to_string(),
        );
    } else if databases.is_empty() {
        log::debug!("No NSS databases found — Firefox/Chromium may not be installed yet");
    } else {
        for db in &databases {
            match install_nss_ca(db, &cert_path_str) {
                Ok(()) => {
                    nss_ok += 1;
                    log::info!("Installed CA into NSS database at {}", db.display());
                }
                Err(e) => {
                    log::warn!("certutil failed for {}: {}", db.display(), e);
                    warnings.push(format!("Could not update {}: {}", db.display(), e));
                }
            }
        }
    }

    if !system_store_ok && nss_ok == 0 {
        return Err(format!(
            "Could not install the CA anywhere. Install it by hand:\n  \
             sudo cp '{}' '{}' && sudo {}",
            cert_path_str,
            anchor.display(),
            store.refresh
        )
        .into());
    }

    let message = match nss_ok {
        0 => "CA certificate installed into the system trust store.".to_string(),
        1 => "CA certificate installed into the system trust store and 1 browser profile."
            .to_string(),
        n => format!(
            "CA certificate installed into the system trust store and {n} browser profiles."
        ),
    };

    Ok(CaInstallResult {
        message,
        cert_path: cert_path_str,
        warnings,
        needs_browser_restart: true,
    })
}

/// Trusted only when the system anchor matches *and* Firefox can see the CA.
/// Checking only the system store would report success on a machine where every
/// HTTPS page still fails in Firefox.
#[cfg(target_os = "linux")]
fn check_ca_trusted_linux(cert_path: &PathBuf) -> Result<bool, BoxErr> {
    let Ok(cert_pem) = std::fs::read_to_string(cert_path) else {
        return Ok(false);
    };

    let anchor = trust_store().anchor_path();
    if !std::fs::read_to_string(&anchor).is_ok_and(|c| c == cert_pem) {
        return Ok(false);
    }

    // Without certutil we can't inspect NSS. Reporting "untrusted" would nag on
    // every launch with no way to fix it, so defer to the dependency prompt.
    if !has_certutil() {
        return Ok(true);
    }

    let databases = nss_databases();
    if databases.is_empty() {
        return Ok(true); // No browser profiles to be wrong about yet.
    }

    Ok(databases.iter().all(nss_has_ca))
}

/// Absolute paths of every NSS database we should install into: Firefox
/// profiles (native, Snap and Flatpak) plus the shared database Chromium,
/// Chrome, Brave and Edge use on Linux.
#[cfg(target_os = "linux")]
fn nss_databases() -> Vec<PathBuf> {
    let Ok(home) = std::env::var("HOME") else {
        return Vec::new();
    };
    let home = PathBuf::from(home);

    let mut dirs: Vec<PathBuf> = [
        ".mozilla/firefox",
        "snap/firefox/common/.mozilla/firefox",
        ".var/app/org.mozilla.firefox/.mozilla/firefox",
        ".librewolf",
        ".var/app/io.gitlab.librewolf-community/.librewolf",
        ".waterfox",
    ]
    .iter()
    .map(|rel| home.join(rel))
    .filter(|base| base.is_dir())
    .flat_map(|base| firefox_profiles_in(&base))
    .collect();

    // Chromium family. Unlike Firefox we never create this one: Chromium builds
    // it on first run, and an empty database we made would just be ignored.
    let chromium_db = home.join(".pki/nssdb");
    if chromium_db.join("cert9.db").exists() {
        dirs.push(chromium_db);
    }

    dirs.sort();
    dirs.dedup();
    dirs
}

/// Profile directories under one Firefox root.
///
/// `profiles.ini` is authoritative — it is the only place that lists profiles
/// stored outside the root directory, and it includes profiles that exist but
/// have never been launched (which have no `cert9.db` yet). A directory scan is
/// merged in as a safety net for profiles missing from the ini.
#[cfg(target_os = "linux")]
fn firefox_profiles_in(base: &std::path::Path) -> Vec<PathBuf> {
    let mut profiles = Vec::new();

    if let Ok(ini) = std::fs::read_to_string(base.join("profiles.ini")) {
        let mut path: Option<String> = None;
        let mut is_relative = true;

        // Sections are terminated by the next header or by end-of-file.
        let flush = |profiles: &mut Vec<PathBuf>, path: &mut Option<String>, relative: bool| {
            if let Some(p) = path.take() {
                profiles.push(if relative {
                    base.join(p)
                } else {
                    PathBuf::from(p)
                });
            }
        };

        for line in ini.lines().map(str::trim) {
            if line.starts_with('[') {
                flush(&mut profiles, &mut path, is_relative);
                is_relative = true;
            } else if let Some(v) = line.strip_prefix("Path=") {
                path = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("IsRelative=") {
                is_relative = v.trim() != "0";
            }
        }
        flush(&mut profiles, &mut path, is_relative);
    }

    if let Ok(entries) = std::fs::read_dir(base) {
        profiles.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.join("prefs.js").exists() || p.join("cert9.db").exists()),
        );
    }

    profiles.retain(|p| p.is_dir());
    profiles
}

/// Add the CA to one NSS database, creating the database if the profile has
/// never been launched.
#[cfg(target_os = "linux")]
fn install_nss_ca(db_dir: &std::path::Path, cert_path: &str) -> Result<(), String> {
    let db = format!("sql:{}", db_dir.display());

    if !db_dir.join("cert9.db").exists() {
        // A brand-new profile has no database yet; certutil -A would fail.
        let _ = certutil(&["-d", db.as_str(), "-N", "--empty-password"]);
    }

    // Remove any older copy first so re-installs after a CA regeneration take.
    let _ = certutil(&["-d", db.as_str(), "-D", "-n", CA_NICKNAME]);

    // Trust flags are SSL,S/MIME,object-signing. `CT` = trusted CA, valid for
    // issuing server certs — the only flag Firefox consults for HTTPS.
    let output = certutil(&[
        "-d",
        db.as_str(),
        "-A",
        "-t",
        "CT,,",
        "-n",
        CA_NICKNAME,
        "-i",
        cert_path,
    ])
    .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(())
    } else {
        Err(first_meaningful_line(&output.stderr)
            .unwrap_or_else(|| "certutil reported an error".to_string()))
    }
}

/// Whether one NSS database already holds our CA.
#[cfg(target_os = "linux")]
fn nss_has_ca(db_dir: &PathBuf) -> bool {
    let db = format!("sql:{}", db_dir.display());
    certutil(&["-d", db.as_str(), "-L", "-n", CA_NICKNAME])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn certutil(args: &[&str]) -> std::io::Result<std::process::Output> {
    std::process::Command::new("certutil").args(args).output()
}

#[cfg(target_os = "linux")]
fn has_certutil() -> bool {
    // NSS certutil exits non-zero for `-H` but still runs, so only the spawn
    // result tells us whether the binary exists.
    certutil(&["-H"]).is_ok()
}

/// Firefox policy files to write, paired with the content each should hold.
///
/// `/etc/firefox/policies` covers distro packages and the Snap (snapd
/// bind-mounts it into the sandbox). `/snap/firefox/...` is deliberately absent:
/// it is a read-only squashfs and writing there can only fail.
#[cfg(target_os = "linux")]
fn firefox_policy_targets(install_path: &str) -> Vec<(PathBuf, String)> {
    let mut dirs = vec![PathBuf::from("/etc/firefox/policies")];
    for base in [
        "/usr/lib/firefox",
        "/usr/lib64/firefox",
        "/usr/lib/firefox-esr",
        "/opt/firefox",
    ] {
        let base = std::path::Path::new(base);
        if base.is_dir() {
            dirs.push(base.join("distribution"));
        }
    }

    dirs.into_iter()
        .map(|dir| {
            let file = dir.join("policies.json");
            let content = merged_policies(&file, install_path);
            (file, content)
        })
        .collect()
}

/// Add our CA to an existing policies.json rather than replacing it — the file
/// is shared with the distro and with any enterprise configuration already in
/// place, and clobbering it would silently drop unrelated policies.
#[cfg(target_os = "linux")]
fn merged_policies(path: &std::path::Path, install_path: &str) -> String {
    use serde_json::{json, Value};

    let mut root = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));

    let policies = root
        .as_object_mut()
        .expect("root is an object")
        .entry("policies")
        .or_insert_with(|| json!({}));
    if !policies.is_object() {
        *policies = json!({});
    }

    let certificates = policies
        .as_object_mut()
        .expect("policies is an object")
        .entry("Certificates")
        .or_insert_with(|| json!({}));
    if !certificates.is_object() {
        *certificates = json!({});
    }

    let certificates = certificates.as_object_mut().expect("object");
    certificates.insert("ImportEnterpriseRoots".into(), json!(true));

    let installs = certificates
        .entry("Install")
        .or_insert_with(|| json!([]))
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut installs: Vec<Value> = installs
        .into_iter()
        .filter(|v| v.as_str().is_some_and(|s| s != install_path))
        .collect();
    installs.push(json!(install_path));
    certificates.insert("Install".into(), Value::Array(installs));

    serde_json::to_string_pretty(&root).unwrap_or_else(|_| {
        format!(
            r#"{{"policies":{{"Certificates":{{"ImportEnterpriseRoots":true,"Install":["{}"]}}}}}}"#,
            install_path
        )
    })
}

/// Build the one privileged script: install the anchor, refresh the bundle, and
/// drop the Firefox policy files.
#[cfg(target_os = "linux")]
fn root_install_script(
    cert_pem: &str,
    store: &TrustStore,
    policies: &[(PathBuf, String)],
) -> String {
    let mut script = String::from("set -e\numask 022\n");

    script.push_str(&format!("mkdir -p {}\n", sh_quote(store.anchor_dir)));
    script.push_str(&heredoc(
        &store.anchor_path().to_string_lossy(),
        cert_pem,
        "PSCERT",
    ));

    // Firefox also resolves bare `Install` filenames out of this directory, so
    // a copy here helps builds that ignore absolute paths.
    script.push_str("mkdir -p /usr/lib/mozilla/certificates\n");
    script.push_str(&heredoc(
        "/usr/lib/mozilla/certificates/packetsniffer-ca.crt",
        cert_pem,
        "PSCERT2",
    ));

    for (i, (path, content)) in policies.iter().enumerate() {
        if let Some(parent) = path.parent() {
            script.push_str(&format!("mkdir -p {}\n", sh_quote(&parent.to_string_lossy())));
        }
        script.push_str(&heredoc(
            &path.to_string_lossy(),
            content,
            &format!("PSPOLICY{i}"),
        ));
    }

    // Last, so that a distro whose refresh tool is unhappy still ends up with
    // the anchor and the Firefox policies on disk.
    script.push_str(&format!("{}\n", store.refresh));

    script
}

/// `cat > <path> <<'MARKER'` … writing `content` verbatim (no shell expansion).
#[cfg(target_os = "linux")]
fn heredoc(path: &str, content: &str, marker: &str) -> String {
    let newline = if content.ends_with('\n') { "" } else { "\n" };
    format!(
        "cat > {} << '{marker}'\n{content}{newline}{marker}\nchmod 644 {}\n",
        sh_quote(path),
        sh_quote(path)
    )
}

/// Single-quote a string for POSIX sh.
#[cfg(target_os = "linux")]
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(target_os = "linux")]
fn run_pkexec(script: &str) -> Result<(), BoxErr> {
    let output = std::process::Command::new("pkexec")
        .args(["sh", "-c", script])
        .output()
        .map_err(|e| format!("could not run pkexec: {e}"))?;

    if output.status.success() {
        return Ok(());
    }

    Err(first_meaningful_line(&output.stderr)
        .unwrap_or_else(|| pkexec_hint(output.status.code()))
        .into())
}

/// pkexec's own exit codes carry no message, so translate the documented ones.
#[cfg(target_os = "linux")]
fn pkexec_hint(code: Option<i32>) -> String {
    match code {
        Some(126) => "the authorization dialog was dismissed".to_string(),
        Some(127) => "authentication failed".to_string(),
        Some(c) => format!("exit code {c}"),
        None => "the process was terminated by a signal".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn has_command(name: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {}", sh_quote(name))])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// First non-blank line of captured output, for surfacing a tool's own error.
#[cfg(target_os = "linux")]
fn first_meaningful_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// Shared policy body for platforms that write a single-purpose policies.json.
#[cfg(target_os = "windows")]
fn firefox_policies_json(ca_cert_path: &str) -> String {
    serde_json::json!({
        "policies": {
            "Certificates": {
                "ImportEnterpriseRoots": true,
                "Install": [ca_cert_path],
            }
        }
    })
    .to_string()
}
