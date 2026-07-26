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
        // A literal IP must go in an iPAddress SAN. Browsers reject a dNSName
        // that holds an address, so a CONNECT to https://192.168.1.5 would fail
        // with SSL_ERROR_BAD_CERT_DOMAIN even though the CA itself is trusted.
        params.subject_alt_names.push(match hostname.parse() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(hostname.try_into()?),
        });
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

        // Insert into cache. Two connections to the same host can race here;
        // return whichever config won so every connection to a host is served
        // the same leaf rather than a per-race duplicate.
        let mut cache = self.ctx_cache.lock().unwrap();
        Ok(Arc::clone(
            cache
                .entry(hostname.to_string())
                .or_insert_with(|| Arc::new(config)),
        ))
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
