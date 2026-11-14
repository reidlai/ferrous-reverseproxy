use clap::Parser;
use ferrous_reverseproxy::config::ZentinelConfig;
use ferrous_reverseproxy::server::ZentinelServer;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(
    name = "ferrous-reverseproxy",
    about = "Zentinel Edge Reverse Proxy with Pure-Rust OWASP WAF for FerrousCX Platform",
    version = env!("CARGO_PKG_VERSION")
)]
struct Args {
    #[arg(short, long, default_value = "config/zentinel.yaml")]
    config: PathBuf,

    #[arg(long)]
    http_port: Option<u16>,

    #[arg(long)]
    https_port: Option<u16>,

    #[arg(long)]
    healthcheck: bool,

    #[arg(long, default_value = "443")]
    health_port: u16,
}

#[derive(Debug)]
struct InsecureCertVerifier;
impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    // Internal container healthcheck probe for zero-OS FROM scratch execution
    if args.healthcheck {
        let target = format!("127.0.0.1:{}", args.health_port);
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::TcpStream::connect(&target),
        )
        .await
        {
            Ok(Ok(stream)) => {
                // If checking the HTTPS port, validate TLS listener responsiveness
                if args.health_port == 443 {
                    let mut client_config = rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(std::sync::Arc::new(InsecureCertVerifier))
                        .with_no_client_auth();
                    client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                    let connector =
                        tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
                    let server_name =
                        rustls_pki_types::ServerName::try_from("localhost".to_string())
                            .map_err(|_| anyhow::anyhow!("Invalid server name"))?;
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        connector.connect(server_name, stream),
                    )
                    .await
                    {
                        Ok(Ok(_tls_stream)) => {
                            tracing::info!("TLS Healthcheck probe succeeded on {}", target);
                            std::process::exit(0);
                        }
                        Ok(Err(e)) => {
                            eprintln!("TLS handshake probe failed on {}: {}", target, e);
                            std::process::exit(1);
                        }
                        Err(_) => {
                            eprintln!("TLS handshake timed out on {}", target);
                            std::process::exit(1);
                        }
                    }
                } else {
                    tracing::info!("Healthcheck TCP probe succeeded on {}", target);
                    std::process::exit(0);
                }
            }
            Ok(Err(e)) => {
                eprintln!("Healthcheck probe failed to connect to {}: {}", target, e);
                std::process::exit(1);
            }
            Err(_) => {
                eprintln!("Healthcheck probe timed out connecting to {}", target);
                std::process::exit(1);
            }
        }
    }

    tracing::info!(
        "Booting Zentinel Edge Reverse Proxy (ferrous-reverseproxy v{})",
        env!("CARGO_PKG_VERSION")
    );

    let mut config = if args.config.exists() {
        tracing::info!("Loading configuration from {}", args.config.display());
        ZentinelConfig::load_from_file(&args.config)?
    } else if std::path::Path::new("/etc/zentinel/zentinel.yaml").exists() {
        tracing::info!("Loading configuration from /etc/zentinel/zentinel.yaml");
        ZentinelConfig::load_from_file("/etc/zentinel/zentinel.yaml")?
    } else {
        tracing::warn!(
            "Config not found at {}. Using defaults with self-signed TLS fallback.",
            args.config.display()
        );
        ZentinelConfig::default()
    };

    if let Some(p) = args.http_port {
        config.server.http_port = p;
    }
    if let Some(p) = args.https_port {
        config.server.https_port = p;
    }

    let server = ZentinelServer::new(config)?;

    // Handle Ctrl+C / SIGINT for graceful shutdown
    let shutdown_tx = server.shutdown_tx();
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            tracing::info!("Received shutdown signal (Ctrl+C), shutting down cleanly...");
            let _ = shutdown_tx.send(());
        }
    });

    // Handle SIGHUP for dynamic rule hot-reload on Unix
    #[cfg(unix)]
    {
        let waf_engine = server.waf();
        let rules_dir = config.waf.rules_dir.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            if let Ok(mut sighup) = signal(SignalKind::hangup()) {
                while sighup.recv().await.is_some() {
                    tracing::info!(
                        "Received SIGHUP! Reloading WAF rules dynamically from {}...",
                        rules_dir
                    );
                    if let Err(e) = waf_engine.reload_from_files(&rules_dir).await {
                        tracing::error!("Failed to reload WAF rules on SIGHUP: {}", e);
                    }
                }
            }
        });
    }

    server.run().await
}
