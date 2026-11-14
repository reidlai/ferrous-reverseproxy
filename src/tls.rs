use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

pub fn load_tls_config<P: AsRef<Path>>(
    cert_path: P,
    key_path: P,
    generate_if_missing: bool,
) -> Result<Arc<ServerConfig>> {
    let cert_exists = cert_path.as_ref().exists();
    let key_exists = key_path.as_ref().exists();

    if cert_exists && key_exists {
        tracing::info!(
            "Loading TLS certificate from {} and private key from {}",
            cert_path.as_ref().display(),
            key_path.as_ref().display()
        );
        let certs = load_certs(cert_path.as_ref())?;
        let key = load_private_key(key_path.as_ref())?;

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to configure TLS server certificate")?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        return Ok(Arc::new(config));
    }

    if generate_if_missing {
        tracing::warn!(
            "TLS cert or key not found at ({}, {}). Generating self-signed certificate for dev/test...",
            cert_path.as_ref().display(),
            key_path.as_ref().display()
        );
        return generate_self_signed_config();
    }

    anyhow::bail!(
        "TLS cert {} or key {} not found and generation disabled",
        cert_path.as_ref().display(),
        key_path.as_ref().display()
    )
}

pub fn generate_self_signed_config() -> Result<Arc<ServerConfig>> {
    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "ferrous-reverseproxy".to_string(),
    ];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("Failed to generate self-signed certificate")?;

    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialized_der().to_vec();

    let cert_chain = vec![CertificateDer::from(cert_der)];
    let private_key = PrivateKeyDer::Pkcs8(key_der.into());

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("Failed to build ServerConfig with self-signed certificate")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("Failed to open cert file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificates")?;
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("Failed to open key file {}", path.display()))?;
    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader).context("Error reading private key item")? {
            Some(rustls_pemfile::Item::Pkcs1Key(k)) => return Ok(PrivateKeyDer::Pkcs1(k)),
            Some(rustls_pemfile::Item::Pkcs8Key(k)) => return Ok(PrivateKeyDer::Pkcs8(k)),
            Some(rustls_pemfile::Item::Sec1Key(k)) => return Ok(PrivateKeyDer::Sec1(k)),
            None => break,
            _ => continue,
        }
    }

    anyhow::bail!("No valid private key found in {}", path.display())
}
