use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::header::{HOST, LOCATION};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub struct RedirectService {
    https_port: u16,
}

impl RedirectService {
    pub fn new(https_port: u16) -> Self {
        Self { https_port }
    }

    pub fn handle_request<B>(&self, req: &Request<B>) -> Response<Empty<Bytes>> {
        let host_header = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");

        // Handle bracketed IPv6 addresses properly (e.g. [::1]:80)
        let host_name = if host_header.starts_with('[') {
            if let Some(end_bracket) = host_header.find(']') {
                &host_header[..=end_bracket]
            } else {
                host_header
            }
        } else {
            host_header.split(':').next().unwrap_or("localhost")
        };

        let uri = req.uri();
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let location = if self.https_port == 443 {
            format!("https://{}{}", host_name, path_and_query)
        } else {
            format!(
                "https://{}:{}{}",
                host_name, self.https_port, path_and_query
            )
        };

        Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(LOCATION, location)
            .header("Connection", "close")
            .body(Empty::new())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Empty::new())
                    .unwrap()
            })
    }
}

pub async fn run_redirect_listener(
    addr: SocketAddr,
    https_port: u16,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        "HTTP redirect listener running on http://{} -> redirecting to HTTPS port {}",
        addr,
        https_port
    );

    let redirect_service = Arc::new(RedirectService::new(https_port));

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, client_addr)) => {
                        let service = redirect_service.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let builder = Builder::new(TokioExecutor::new());
                            let conn = builder.serve_connection_with_upgrades(
                                io,
                                service_fn(move |req| {
                                    let s = service.clone();
                                    async move { Ok::<_, hyper::Error>(s.handle_request(&req)) }
                                }),
                            );
                            if let Ok(res) = tokio::time::timeout(std::time::Duration::from_secs(5), conn).await
                                && let Err(err) = res {
                                    tracing::debug!("Redirect connection error from {}: {}", client_addr, err);
                                }
                        });
                    }
                    Err(err) => {
                        tracing::warn!("Redirect listener accept error: {}. Backing off 100ms...", err);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Shutting down HTTP redirect listener on {}", addr);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    #[test]
    fn test_redirect_to_standard_https() {
        let redirect = RedirectService::new(443);
        let req = Request::builder()
            .header("Host", "example.com:80")
            .uri("/api/v1/orders?filter=active")
            .body(())
            .unwrap();

        let res = redirect.handle_request(&req);
        assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            res.headers().get("Location").unwrap(),
            "https://example.com/api/v1/orders?filter=active"
        );
    }

    #[test]
    fn test_redirect_to_custom_https_port() {
        let redirect = RedirectService::new(8443);
        let req = Request::builder()
            .header("Host", "localhost")
            .uri("/dashboard")
            .body(())
            .unwrap();

        let res = redirect.handle_request(&req);
        assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            res.headers().get("Location").unwrap(),
            "https://localhost:8443/dashboard"
        );
    }
}
