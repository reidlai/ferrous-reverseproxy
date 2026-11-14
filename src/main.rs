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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
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
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut sighup) = signal(SignalKind::hangup()) {
                while sighup.recv().await.is_some() {
                    tracing::info!("Received SIGHUP! Reloading WAF rules dynamically...");
                    if let Err(e) = waf_engine.reload_from_files("/etc/zentinel/rules.d").await {
                        tracing::error!("Failed to reload WAF rules on SIGHUP: {}", e);
                    }
                }
            }
        });
    }

    server.run().await
}
