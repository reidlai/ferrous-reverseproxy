use crate::config::ZentinelConfig;
use crate::proxy::ReverseProxyService;
use crate::redirect::run_redirect_listener;
use crate::router::Router;
use crate::tls::load_tls_config;
use crate::waf::WafEngine;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

pub struct ZentinelServer {
    config: ZentinelConfig,
    router: Arc<Router>,
    waf: Arc<WafEngine>,
    shutdown_tx: broadcast::Sender<()>,
}

impl ZentinelServer {
    pub fn new(config: ZentinelConfig) -> anyhow::Result<Self> {
        let router = Arc::new(Router::new(&config));
        let waf = Arc::new(WafEngine::new(
            config.waf.enabled,
            config.waf.block_mode == "block",
        )?);

        // Start background Day-0 rule file watcher if rules_dir exists
        if std::path::Path::new(&config.waf.rules_dir).exists()
            && let Err(e) = waf.start_file_watcher(&config.waf.rules_dir)
        {
            tracing::warn!("Failed to start Day-0 rule file watcher: {}", e);
        }

        let (shutdown_tx, _) = broadcast::channel(16);

        Ok(Self {
            config,
            router,
            waf,
            shutdown_tx,
        })
    }

    pub fn waf(&self) -> Arc<WafEngine> {
        self.waf.clone()
    }

    pub fn shutdown_tx(&self) -> broadcast::Sender<()> {
        self.shutdown_tx.clone()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let http_addr: SocketAddr = format!("0.0.0.0:{}", self.config.server.http_port).parse()?;
        let https_addr: SocketAddr =
            format!("0.0.0.0:{}", self.config.server.https_port).parse()?;

        // 1. Spawn HTTP Port 80 Redirect Listener
        let redirect_shutdown_rx = self.shutdown_tx.subscribe();
        let https_port = self.config.server.https_port;
        tokio::spawn(async move {
            if let Err(e) = run_redirect_listener(http_addr, https_port, redirect_shutdown_rx).await
            {
                tracing::error!("HTTP redirect listener failed: {}", e);
            }
        });

        // 2. Setup Port 443 HTTPS TLS Listener
        let tls_server_config = load_tls_config(
            &self.config.server.tls.cert_path,
            &self.config.server.tls.key_path,
            self.config.server.tls.generate_self_signed_if_missing,
        )?;
        let tls_acceptor = TlsAcceptor::from(tls_server_config);

        let listener = TcpListener::bind(https_addr).await?;
        tracing::info!(
            "Zentinel Edge Proxy HTTPS listener active on https://{} (terminating TLS)",
            https_addr
        );

        let proxy_service = Arc::new(ReverseProxyService::new(
            self.router.clone(),
            self.waf.clone(),
            https_port,
        ));

        // Enforce maximum concurrent active connections to guarantee <40MB RAM budget
        let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(1024));
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((tcp_stream, client_addr)) => {
                            let acceptor = tls_acceptor.clone();
                            let service = proxy_service.clone();
                            let permit = match conn_semaphore.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::warn!("Max connections reached (1024), shedding load from {}", client_addr);
                                    drop(tcp_stream);
                                    continue;
                                }
                            };

                            tokio::spawn(async move {
                                let _permit = permit;
                                // Enforce 10s TLS handshake timeout (Slowloris defense)
                                let tls_handshake = tokio::time::timeout(
                                    std::time::Duration::from_secs(10),
                                    acceptor.accept(tcp_stream),
                                );
                                match tls_handshake.await {
                                    Ok(Ok(tls_stream)) => {
                                        let io = TokioIo::new(tls_stream);
                                        let builder = Builder::new(TokioExecutor::new());
                                        let conn = builder.serve_connection_with_upgrades(
                                            io,
                                            hyper::service::service_fn(move |req| {
                                                let s = service.clone();
                                                async move { s.handle_request(req, client_addr).await }
                                            }),
                                        );
                                        if let Err(err) = conn.await {
                                            tracing::debug!("Connection error with {}: {}", client_addr, err);
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        tracing::debug!("TLS handshake failed with {}: {}", client_addr, e);
                                    }
                                    Err(_) => {
                                        tracing::warn!("TLS handshake timed out after 10s with {}", client_addr);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("HTTPS accept error: {}. Backing off 100ms...", e);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("Received shutdown signal. Zentinel proxy terminating cleanly.");
                    break;
                }
            }
        }

        Ok(())
    }
}
