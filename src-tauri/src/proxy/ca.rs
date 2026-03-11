// ─── Certificate Authority ───────────────────────────────────────────────────
// Generates a self-signed root CA and per-host leaf certificates using `rcgen`.
// Mirrors the C++ CertificateAuthority: root CA gen/load/save, per-host cert
// with SAN, and a TLS ServerConfig cache keyed by hostname.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Bump this whenever cert generation parameters change so stale certs
/// are automatically regenerated on startup.
const CA_VERSION: &str = "2";

/// The Certificate Authority that generates and caches per-host TLS configs.
pub struct CertificateAuthority {
    ca_dir: PathBuf,
    ca_cert_pem: String,
    ca_key_pem: String,
    ca_cert_der: CertificateDer<'static>,
    ca_key_pair: KeyPair,
    /// Cache of hostname -> Arc<ServerConfig>
    ctx_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertificateAuthority {
    /// Initialize the CA. Loads existing ca-cert.pem / ca-key.pem from `ca_dir`,
    /// or generates a new root CA if they don't exist.
    pub fn initialize(ca_dir: Option<&Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = match ca_dir {
            Some(d) => d.to_path_buf(),
            None => default_ca_dir()?,
        };

        std::fs::create_dir_all(&dir)?;

        let cert_path = dir.join("ca-cert.pem");
        let key_path = dir.join("ca-key.pem");
        let version_path = dir.join("ca-version");

        // Check if the cert version matches; if not, regenerate
        let version_ok = version_path
            .exists()
            && std::fs::read_to_string(&version_path)
                .map(|v| v.trim() == CA_VERSION)
                .unwrap_or(false);

        if cert_path.exists() && key_path.exists() && version_ok {
            // Load existing
            let cert_pem = std::fs::read_to_string(&cert_path)?;
            let key_pem = std::fs::read_to_string(&key_path)?;
            Self::from_pem(&dir, &cert_pem, &key_pem)
        } else {
            // Generate new (or regenerate stale cert)
            if cert_path.exists() {
                log::info!("CA version mismatch — regenerating certificates");
            }
            let ca = Self::generate_new(&dir)?;
            std::fs::write(&cert_path, &ca.ca_cert_pem)?;
            std::fs::write(&key_path, &ca.ca_key_pem)?;
            std::fs::write(&version_path, CA_VERSION)?;
            log::info!("Generated new root CA in {}", dir.display());
            Ok(ca)
        }
    }

    /// Force regenerate the CA cert and key (e.g. when the old cert used wrong parameters).
    #[allow(dead_code)]
    pub fn regenerate(ca_dir: Option<&Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = match ca_dir {
            Some(d) => d.to_path_buf(),
            None => default_ca_dir()?,
        };
        std::fs::create_dir_all(&dir)?;

        let cert_path = dir.join("ca-cert.pem");
        let key_path = dir.join("ca-key.pem");
        let version_path = dir.join("ca-version");

        let ca = Self::generate_new(&dir)?;
        std::fs::write(&cert_path, &ca.ca_cert_pem)?;
        std::fs::write(&key_path, &ca.ca_key_pem)?;
        std::fs::write(&version_path, CA_VERSION)?;
        log::info!("Regenerated root CA in {}", dir.display());
        Ok(ca)
    }

    /// Construct from existing PEM strings.
    fn from_pem(
        ca_dir: &Path,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let key_pair = KeyPair::from_pem(key_pem)?;

        // Parse the DER from the PEM cert
        let ca_cert_der = pem_to_der(cert_pem)?;

        Ok(Self {
            ca_dir: ca_dir.to_path_buf(),
            ca_cert_pem: cert_pem.to_string(),
            ca_key_pem: key_pem.to_string(),
            ca_cert_der,
            ca_key_pair: key_pair,
            ctx_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Generate a fresh self-signed RSA root CA (10-year validity).
    fn generate_new(ca_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CountryName, "US");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "PacketSniffer Dev CA");
        params
            .distinguished_name
            .push(DnType::CommonName, "PacketSniffer Root CA");

        // 10-year validity with 1-minute grace for clock skew
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - Duration::from_secs(60);
        params.not_after = now + Duration::from_secs(10 * 365 * 24 * 3600);

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key_pair)?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let ca_cert_der = CertificateDer::from(cert.der().to_vec());

        Ok(Self {
            ca_dir: ca_dir.to_path_buf(),
            ca_cert_pem: cert_pem,
            ca_key_pem: key_pem,
            ca_cert_der,
            ca_key_pair: key_pair,
            ctx_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Get (or create and cache) a rustls `ServerConfig` for the given hostname.
    /// The leaf certificate is signed by this CA and includes SAN: DNS:<hostname>.
    pub fn server_config_for_host(
        &self,
        hostname: &str,
    ) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        // Check cache
        {
            let cache = self.ctx_cache.lock().unwrap();
            if let Some(cfg) = cache.get(hostname) {
                return Ok(Arc::clone(cfg));
            }
        }

        // Generate leaf cert
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.distinguished_name.push(DnType::CommonName, hostname);
        params
            .subject_alt_names
            .push(SanType::DnsName(hostname.try_into()?));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // 1-year validity with 1-minute grace for clock skew
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - Duration::from_secs(60);
        params.not_after = now + Duration::from_secs(365 * 24 * 3600);

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

        // Build an Issuer from the existing CA cert DER + key pair
        let issuer = Issuer::from_ca_cert_der(&self.ca_cert_der, &self.ca_key_pair)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

        let leaf_cert = params.signed_by(&leaf_key, &issuer)?;

        // Build rustls ServerConfig
        let leaf_der = CertificateDer::from(leaf_cert.der().to_vec());
        let ca_der = self.ca_cert_der.clone();
        let leaf_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der, ca_der], leaf_key_der)?;

        // Advertise HTTP/2 + HTTP/1.1 via ALPN so browsers can negotiate h2
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let config = Arc::new(config);

        // Insert into cache
        {
            let mut cache = self.ctx_cache.lock().unwrap();
            cache
                .entry(hostname.to_string())
                .or_insert_with(|| Arc::clone(&config));
        }

        Ok(config)
    }

    /// Path to the CA certificate PEM file.
    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_dir.join("ca-cert.pem")
    }
}

/// Extract the first DER certificate from a PEM string.
fn pem_to_der(pem: &str) -> Result<CertificateDer<'static>, Box<dyn std::error::Error>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    certs
        .into_iter()
        .next()
        .ok_or_else(|| "No certificate found in PEM".into())
}

/// Default CA directory: ~/.packetsniffer/
fn default_ca_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let proj_dirs = directories::ProjectDirs::from("com", "packetsniffer", "PacketSniffer")
        .ok_or("Cannot determine home directory")?;
    Ok(proj_dirs.data_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_ca_initialization() {
        // Test that CA can be initialized
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca");
        let _ = fs::remove_dir_all(&temp_dir); // Clean up if exists
        fs::create_dir_all(&temp_dir).unwrap();

        let result = CertificateAuthority::initialize(Some(&temp_dir));
        assert!(result.is_ok());

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ca_initialization_creates_files() {
        // Test that CA initialization creates certificate files
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca_files");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let ca = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();

        // Check that cert file exists
        assert!(temp_dir.join("ca-cert.pem").exists());
        assert!(temp_dir.join("ca-key.pem").exists());
        assert!(temp_dir.join("ca-version").exists());

        // Check ca_cert_path method
        assert_eq!(ca.ca_cert_path(), temp_dir.join("ca-cert.pem"));

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ca_reinitialization_loads_existing() {
        // Test that re-initializing loads existing CA
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca_reload");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // First initialization
        let ca1 = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();
        let cert_pem1 = fs::read_to_string(temp_dir.join("ca-cert.pem")).unwrap();

        // Second initialization should load the same certificate
        let ca2 = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();
        let cert_pem2 = fs::read_to_string(temp_dir.join("ca-cert.pem")).unwrap();

        assert_eq!(cert_pem1, cert_pem2);
        assert_eq!(ca1.ca_cert_path(), ca2.ca_cert_path());

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ca_regenerate() {
        // Test that CA can be regenerated
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca_regen");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // First generation
        let ca1 = CertificateAuthority::regenerate(Some(&temp_dir)).unwrap();
        let cert_pem1 = fs::read_to_string(temp_dir.join("ca-cert.pem")).unwrap();

        // Regenerate
        let ca2 = CertificateAuthority::regenerate(Some(&temp_dir)).unwrap();
        let cert_pem2 = fs::read_to_string(temp_dir.join("ca-cert.pem")).unwrap();

        // Certificates should be different (new generation)
        assert_ne!(cert_pem1, cert_pem2);
        assert_eq!(ca1.ca_cert_path(), ca2.ca_cert_path());

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_server_config_for_host() {
        // Test generating server config for a hostname
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca_host");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let ca = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();

        let result = ca.server_config_for_host("example.com");
        assert!(result.is_ok());

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_server_config_caching() {
        // Test that server configs are cached
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca_cache");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let ca = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();

        // Generate config twice for same hostname
        let config1 = ca.server_config_for_host("example.com").unwrap();
        let config2 = ca.server_config_for_host("example.com").unwrap();

        // Should return the same Arc
        assert!(Arc::ptr_eq(&config1, &config2));

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_server_config_different_hosts() {
        // Test generating configs for different hostnames
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca_hosts");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let ca = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();

        let config1 = ca.server_config_for_host("example.com").unwrap();
        let config2 = ca.server_config_for_host("test.com").unwrap();

        // Should be different configs
        assert!(!Arc::ptr_eq(&config1, &config2));

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_server_config_alpn_protocols() {
        // Test that generated server configs include ALPN protocols
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca_alpn");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let ca = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();
        let config = ca.server_config_for_host("example.com").unwrap();

        // Check that ALPN protocols are set
        assert!(!config.alpn_protocols.is_empty());
        assert_eq!(config.alpn_protocols[0], b"h2");
        assert_eq!(config.alpn_protocols[1], b"http/1.1");

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_default_ca_dir() {
        // Test that default_ca_dir returns a path
        let result = default_ca_dir();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_ca_version_constant() {
        // Test that CA_VERSION is not empty
        assert!(!CA_VERSION.is_empty());
        assert!(CA_VERSION.len() > 0);
    }

    #[test]
    fn test_ca_version_check() {
        // Test that version mismatch triggers regeneration
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca_version");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // Create initial CA
        let _ca1 = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();
        let cert_pem1 = fs::read_to_string(temp_dir.join("ca-cert.pem")).unwrap();

        // Manually change version file to trigger regeneration
        fs::write(temp_dir.join("ca-version"), "old-version").unwrap();

        // Reinitialize should regenerate due to version mismatch
        let _ca2 = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();
        let cert_pem2 = fs::read_to_string(temp_dir.join("ca-cert.pem")).unwrap();

        // Certificates should be different due to regeneration
        assert_ne!(cert_pem1, cert_pem2);

        // Version file should be updated to current version
        let version = fs::read_to_string(temp_dir.join("ca-version")).unwrap();
        assert_eq!(version.trim(), CA_VERSION);

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_server_config_for_localhost() {
        // Test generating config for localhost
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_ca_localhost");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let ca = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();

        let result = ca.server_config_for_host("localhost");
        assert!(result.is_ok());

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pem_to_der() {
        // Test pem_to_der with valid PEM
        let temp_dir = std::env::temp_dir().join("packetsniffer_test_pem");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let ca = CertificateAuthority::initialize(Some(&temp_dir)).unwrap();
        let cert_pem = fs::read_to_string(temp_dir.join("ca-cert.pem")).unwrap();

        let result = pem_to_der(&cert_pem);
        assert!(result.is_ok());

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pem_to_der_with_invalid_pem() {
        // Test pem_to_der with invalid PEM
        let result = pem_to_der("not a valid pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_ca_initialization_creates_directory() {
        // Test that CA initialization creates the directory if it doesn't exist
        let temp_dir = std::env::temp_dir()
            .join("packetsniffer_test_ca_newdir")
            .join("subdir");
        let _ = fs::remove_dir_all(&temp_dir);

        let result = CertificateAuthority::initialize(Some(&temp_dir));
        assert!(result.is_ok());
        assert!(temp_dir.exists());

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }
}