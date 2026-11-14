use crate::router::{ResolvedRoute, Router};
use crate::waf::WafEngine;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderValue, HOST};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

fn strip_hop_by_hop_headers(headers: &mut hyper::HeaderMap) {
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

#[derive(Clone)]
pub struct ReverseProxyService {
    router: Arc<Router>,
    waf: Arc<WafEngine>,
    https_port: u16,
}

impl ReverseProxyService {
    pub fn new(router: Arc<Router>, waf: Arc<WafEngine>, https_port: u16) -> Self {
        Self {
            router,
            waf,
            https_port,
        }
    }

    pub async fn handle_request<B>(
        &self,
        req: Request<B>,
        client_addr: SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
    where
        B: hyper::body::Body<Data = Bytes> + Send + Sync + 'static,
        B::Error: std::fmt::Debug + Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let method = req.method().to_string();
        let uri = req.uri().to_string();
        let headers = req.headers().clone();

        // 1. Healthcheck Endpoint Check (Internal reverse proxy probe on /health or /healthz)
        if req.uri().path() == "/health" || req.uri().path() == "/healthz" {
            let res = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(BoxBody::new(
                    Full::new(Bytes::from(r#"{"status":"healthy","service":"ferrous-reverseproxy"}"#))
                        .map_err(|e| match e {}),
                ))
                .unwrap();
            return Ok(res);
        }

        // 2. WAF Inspection (Phase 1 Headers/URI & Phase 2 Body for mutating requests)
        let is_mutating = req.method() == hyper::Method::POST
            || req.method() == hyper::Method::PUT
            || req.method() == hyper::Method::PATCH;

        let (parts, body) = req.into_parts();
        let (reconstructed_body, waf_result) = if is_mutating {
            // Buffer mutating body for WAF inspection (max 1MB)
            match body.collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    let res = self
                        .waf
                        .inspect_request_with_body(&method, &uri, &headers, Some(&bytes))
                        .await;
                    let reconstructed: BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>> =
                        BoxBody::new(Full::new(bytes).map_err(|e| match e {}));
                    (reconstructed, res)
                }
                Err(err) => {
                    tracing::warn!("Failed to read request body: {:?}", err);
                    let empty: BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>> =
                        BoxBody::new(Full::new(Bytes::new()).map_err(|e| match e {}));
                    (
                        empty,
                        self.waf
                            .inspect_request_with_body(&method, &uri, &headers, None)
                            .await,
                    )
                }
            }
        } else {
            let boxed: BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>> =
                BoxBody::new(body.map_err(Into::into));
            (
                boxed,
                self.waf
                    .inspect_request_with_body(&method, &uri, &headers, None)
                    .await,
            )
        };

        if waf_result.blocked {
            tracing::warn!(
                "WAF BLOCKED {} {} from {}: {}",
                method,
                uri,
                client_addr,
                waf_result.message.as_deref().unwrap_or("Forbidden")
            );
            let body_json = serde_json::json!({
                "error": "Forbidden",
                "status": 403,
                "message": waf_result.message.unwrap_or_else(|| "Blocked by OWASP CRS / Zentinel WAF".to_string())
            });
            let body_bytes = serde_json::to_vec(&body_json).unwrap_or_default();
            let res = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .header("X-Content-Type-Options", "nosniff")
                .body(BoxBody::new(Full::new(Bytes::from(body_bytes)).map_err(|e| match e {})))
                .unwrap();
            return Ok(res);
        }

        let reconstructed_req = Request::from_parts(parts, reconstructed_body);

        // 3. Route Resolution
        let path = reconstructed_req.uri().path();
        let resolved = match self.router.resolve(path) {
            Some(r) => r,
            None => {
                tracing::warn!("No route matched for path: {}", path);
                let res = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("Content-Type", "application/json")
                    .body(BoxBody::new(
                        Full::new(Bytes::from(r#"{"error":"Not Found","status":404}"#))
                            .map_err(|e| match e {}),
                    ))
                    .unwrap();
                return Ok(res);
            }
        };

        // 4. Forward Request to Upstream
        self.forward_to_upstream(reconstructed_req, client_addr, resolved).await
    }

    async fn forward_to_upstream<B>(
        &self,
        req: Request<B>,
        client_addr: SocketAddr,
        route: ResolvedRoute,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (parts, body) = req.into_parts();
        let timeout_dur = Duration::from_millis(route.timeout_ms);

        // Connect to primary target or fallback with configured timeout
        let stream = match tokio::time::timeout(timeout_dur, TcpStream::connect(&route.upstream_target)).await {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => {
                if let Some(fallback) = &route.fallback_target {
                    tracing::debug!(
                        "Upstream target {} failed ({}), trying fallback {}",
                        route.upstream_target,
                        err,
                        fallback
                    );
                    match tokio::time::timeout(timeout_dur, TcpStream::connect(fallback)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(fallback_err)) => {
                            tracing::error!(
                                "Both target {} and fallback {} failed: {}, {}",
                                route.upstream_target,
                                fallback,
                                err,
                                fallback_err
                            );
                            return Ok(Self::bad_gateway_response(
                                &route.upstream_target,
                                fallback_err,
                            ));
                        }
                        Err(_) => {
                            return Ok(Self::bad_gateway_response(fallback, "Connection timed out"));
                        }
                    }
                } else {
                    tracing::error!("Failed to connect to upstream {}: {}", route.upstream_target, err);
                    return Ok(Self::bad_gateway_response(&route.upstream_target, err));
                }
            }
            Err(_) => {
                if let Some(fallback) = &route.fallback_target {
                    match tokio::time::timeout(timeout_dur, TcpStream::connect(fallback)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(fallback_err)) => {
                            return Ok(Self::bad_gateway_response(&route.upstream_target, fallback_err));
                        }
                        Err(_) => {
                            return Ok(Self::bad_gateway_response(fallback, "Connection timed out"));
                        }
                    }
                } else {
                    return Ok(Self::bad_gateway_response(&route.upstream_target, "Connection timed out"));
                }
            }
        };

        let io = TokioIo::new(stream);
        let (mut sender, conn) = match tokio::time::timeout(timeout_dur, hyper::client::conn::http1::handshake(io)).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                tracing::error!("HTTP/1 handshake with upstream failed: {}", e);
                return Ok(Self::bad_gateway_response(&route.upstream_target, e));
            }
            Err(_) => {
                return Ok(Self::bad_gateway_response(&route.upstream_target, "Handshake timed out"));
            }
        };

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                tracing::debug!("Upstream connection closed: {:?}", err);
            }
        });

        // Reconstruct client request for upstream
        let mut forward_req = Request::new(body);
        *forward_req.method_mut() = parts.method;
        // Normalize version to HTTP/1.1 for HTTP/1 upstream (never forward HTTP/2 downstream version)
        *forward_req.version_mut() = hyper::Version::HTTP_11;

        // Path and query
        let query = parts.uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let target_uri = format!("{}{}", route.forwarded_path, query);
        if let Ok(uri) = target_uri.parse() {
            *forward_req.uri_mut() = uri;
        }

        // Copy headers and strip hop-by-hop headers
        *forward_req.headers_mut() = parts.headers;
        strip_hop_by_hop_headers(forward_req.headers_mut());

        // Preserve original host in X-Forwarded-Host before rewriting Host
        if let Some(orig_host) = forward_req.headers().get(HOST).cloned() {
            forward_req.headers_mut().insert("X-Forwarded-Host", orig_host);
        }

        if let Ok(host_val) = route.upstream_target.parse() {
            forward_req.headers_mut().insert(HOST, host_val);
        }

        // Append to X-Forwarded-For
        let client_ip = client_addr.ip().to_string();
        let xff_value = match forward_req.headers().get("X-Forwarded-For") {
            Some(existing) => {
                if let Ok(s) = existing.to_str() {
                    format!("{}, {}", s, client_ip)
                } else {
                    client_ip
                }
            }
            None => client_ip,
        };
        if let Ok(v) = HeaderValue::from_str(&xff_value) {
            forward_req.headers_mut().insert("X-Forwarded-For", v);
        }

        forward_req
            .headers_mut()
            .insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
        forward_req
            .headers_mut()
            .insert("X-Forwarded-Port", HeaderValue::from(self.https_port));

        // Forward request with configured timeout
        let upstream_res = match tokio::time::timeout(timeout_dur, sender.send_request(forward_req)).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                tracing::error!("Error forwarding request to upstream: {}", e);
                return Ok(Self::bad_gateway_response(&route.upstream_target, e));
            }
            Err(_) => {
                tracing::error!("Request to upstream {} timed out after {}ms", route.upstream_target, route.timeout_ms);
                return Ok(Self::bad_gateway_response(&route.upstream_target, "Request timed out"));
            }
        };

        // Construct client response
        let (res_parts, res_body) = upstream_res.into_parts();
        let mut client_res = Response::builder()
            .status(res_parts.status)
            .version(res_parts.version);

        *client_res.headers_mut().unwrap() = res_parts.headers;
        strip_hop_by_hop_headers(client_res.headers_mut().unwrap());

        // Ensure unbuffered streaming for SSE and token streams (X-Accel-Buffering: no)
        let is_sse = client_res
            .headers_ref()
            .and_then(|h| h.get("Content-Type"))
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("text/event-stream"));

        if is_sse {
            client_res
                .headers_mut()
                .unwrap()
                .insert("X-Accel-Buffering", HeaderValue::from_static("no"));
            client_res
                .headers_mut()
                .unwrap()
                .insert("Cache-Control", HeaderValue::from_static("no-cache, no-transform"));
        } else if route.unbuffered_streaming {
            client_res
                .headers_mut()
                .unwrap()
                .insert("X-Accel-Buffering", HeaderValue::from_static("no"));
        }

        // Stream body directly to client with zero intermediate buffering
        let boxed_body: BoxBody<Bytes, hyper::Error> = BoxBody::new(res_body);
        Ok(client_res.body(boxed_body).unwrap())
    }

    fn bad_gateway_response<E: std::fmt::Display>(
        target: &str,
        err: E,
    ) -> Response<BoxBody<Bytes, hyper::Error>> {
        let msg = serde_json::json!({
            "error": "Bad Gateway",
            "status": 502,
            "target": target,
            "details": format!("{}", err)
        });
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .body(BoxBody::new(
                Full::new(Bytes::from(serde_json::to_vec(&msg).unwrap_or_default()))
                    .map_err(|e| match e {}),
            ))
            .unwrap()
    }
}
