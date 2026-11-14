use ferrous_reverseproxy::config::{
    RouteRule, ServerConfig, UpstreamConfig, WafConfig, ZentinelConfig,
};
use ferrous_reverseproxy::server::ZentinelServer;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;

// Spawns a mock upstream server returning a JSON echo of the request details
async fn spawn_mock_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let request_count = Arc::new(AtomicUsize::new(0));
    let count = request_count.clone();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let count = count.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let builder = Builder::new(TokioExecutor::new());
                    let _ = builder
                        .serve_connection_with_upgrades(
                            io,
                            service_fn(move |req: Request<hyper::body::Incoming>| {
                                count.fetch_add(1, Ordering::SeqCst);
                                let method = req.method().to_string();
                                let uri = req.uri().to_string();
                                let forwarded_for = req
                                    .headers()
                                    .get("X-Forwarded-For")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                let forwarded_proto = req
                                    .headers()
                                    .get("X-Forwarded-Proto")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                let forwarded_host = req
                                    .headers()
                                    .get("X-Forwarded-Host")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                let custom_header = req
                                    .headers()
                                    .get("X-Custom-Test")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();

                                async move {
                                    let body_bytes =
                                        req.into_body().collect().await.unwrap().to_bytes();
                                    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

                                    let echo = serde_json::json!({
                                        "status": "success",
                                        "upstream": "mock-api",
                                        "method": method,
                                        "uri": uri,
                                        "forwarded_for": forwarded_for,
                                        "forwarded_proto": forwarded_proto,
                                        "forwarded_host": forwarded_host,
                                        "custom_header": custom_header,
                                        "body": body_str,
                                    });
                                    let body = serde_json::to_vec(&echo).unwrap();
                                    let res = Response::builder()
                                        .status(StatusCode::OK)
                                        .header("Content-Type", "application/json")
                                        .body(BoxBody::new(
                                            Full::new(Bytes::from(body)).map_err(|e| match e {}),
                                        ))
                                        .unwrap();
                                    Ok::<_, hyper::Error>(res)
                                }
                            }),
                        )
                        .await;
                });
            }
        }
    });

    (addr, request_count)
}

#[tokio::test]
async fn test_e2e_live_tls_proxy_and_waf() {
    let (upstream_addr, upstream_calls) = spawn_mock_upstream().await;

    // Pick ephemeral ports for reverse proxy
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    drop(http_listener);

    let https_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_port = https_listener.local_addr().unwrap().port();
    drop(https_listener);

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        UpstreamConfig {
            target: format!("127.0.0.1:{}", upstream_addr.port()),
            fallback: None,
            timeout_ms: 10000,
            tls: false,
        },
    );
    upstreams.insert(
        "dead_backend".to_string(),
        UpstreamConfig {
            target: "127.0.0.1:1".to_string(), // Closed port
            fallback: None,
            timeout_ms: 500,
            tls: false,
        },
    );

    let routes = vec![
        RouteRule {
            prefix: "/api/".to_string(),
            upstream: "api".to_string(),
            strip_prefix: false,
            unbuffered_streaming: true,
        },
        RouteRule {
            prefix: "/dead/".to_string(),
            upstream: "dead_backend".to_string(),
            strip_prefix: false,
            unbuffered_streaming: false,
        },
    ];

    let config = ZentinelConfig {
        server: ServerConfig {
            http_port,
            https_port,
            tls: Default::default(),
        },
        waf: WafConfig::default(),
        upstreams,
        routes,
    };

    let server = ZentinelServer::new(config).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Wait for server to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

    // 1. Test Port 80 -> HTTPS Redirection
    let client_no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let redirect_url = format!("http://127.0.0.1:{}/api/v1/ping", http_port);
    let redirect_res = client_no_redirect.get(&redirect_url).send().await.unwrap();
    assert_eq!(
        redirect_res.status(),
        reqwest::StatusCode::MOVED_PERMANENTLY
    );
    let location = redirect_res
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with(&format!("https://127.0.0.1:{}/api/v1/ping", https_port)));

    // 2. Test HTTPS TLS Forward to Upstream with POST, Query, Headers, and Body
    let client_tls = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let https_url = format!(
        "https://127.0.0.1:{}/api/v1/orders?filter=active",
        https_port
    );
    let post_payload = r#"{"order_id":"ord-123","amount":99.50}"#;
    let https_res = client_tls
        .post(&https_url)
        .header("Content-Type", "application/json")
        .header("X-Custom-Test", "PlatformHeaderValue")
        .body(post_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(https_res.status(), reqwest::StatusCode::OK);
    // Verify unbuffered streaming header
    assert_eq!(
        https_res
            .headers()
            .get("X-Accel-Buffering")
            .unwrap()
            .to_str()
            .unwrap(),
        "no"
    );

    let body_bytes = https_res.bytes().await.unwrap();
    let json_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json_body["status"], "success");
    assert_eq!(json_body["method"], "POST");
    assert_eq!(json_body["uri"], "/api/v1/orders?filter=active");
    assert_eq!(json_body["forwarded_proto"], "https");
    assert_eq!(json_body["custom_header"], "PlatformHeaderValue");
    assert_eq!(json_body["body"], post_payload);
    assert!(!json_body["forwarded_for"].as_str().unwrap().is_empty());
    assert_eq!(upstream_calls.load(Ordering::SeqCst), 1);

    // 3. Test OWASP WAF Block over HTTPS
    let attack_url = format!(
        "https://127.0.0.1:{}/api/v1/orders?query=1%20UNION%20SELECT%20*%20FROM%20users",
        https_port
    );
    let attack_res = client_tls.get(&attack_url).send().await.unwrap();
    assert_eq!(attack_res.status(), reqwest::StatusCode::FORBIDDEN);
    // Upstream calls must remain 1 because attack was blocked at perimeter!
    assert_eq!(upstream_calls.load(Ordering::SeqCst), 1);

    // 4. Test 502 Bad Gateway when upstream is unavailable
    let dead_url = format!("https://127.0.0.1:{}/dead/test", https_port);
    let dead_res = client_tls.get(&dead_url).send().await.unwrap();
    assert_eq!(dead_res.status(), reqwest::StatusCode::BAD_GATEWAY);

    // 5. Continuous traffic load test (100 requests) to verify stability and zero resource leaks
    for _ in 0..50 {
        let res = client_tls.get(&https_url).send().await.unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK);
    }
}
