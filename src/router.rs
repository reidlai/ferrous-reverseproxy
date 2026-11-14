use crate::config::{RouteRule, UpstreamConfig, ZentinelConfig};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Router {
    routes: Vec<RouteRule>,
    upstreams: HashMap<String, UpstreamConfig>,
}

#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    pub upstream_target: String,
    pub fallback_target: Option<String>,
    pub timeout_ms: u64,
    pub tls: bool,
    pub unbuffered_streaming: bool,
    pub forwarded_path: String,
}

impl Router {
    pub fn new(config: &ZentinelConfig) -> Self {
        let mut routes = config.routes.clone();
        // Sort routes by prefix length descending to ensure longest prefix matches first
        routes.sort_by_key(|a| std::cmp::Reverse(a.prefix.len()));
        Self {
            routes,
            upstreams: config.upstreams.clone(),
        }
    }

    pub fn resolve(&self, path: &str) -> Option<ResolvedRoute> {
        for route in &self.routes {
            let prefix_trimmed = route.prefix.trim_end_matches('/');
            let matches = if prefix_trimmed.is_empty() {
                // Root route matches everything
                path.starts_with('/')
            } else {
                path == prefix_trimmed || path.starts_with(&route.prefix)
            };

            if matches && let Some(upstream) = self.upstreams.get(&route.upstream) {
                let forwarded_path = if route.strip_prefix {
                    let stripped = path
                        .strip_prefix(&route.prefix)
                        .or_else(|| path.strip_prefix(prefix_trimmed))
                        .unwrap_or(path);
                    if stripped.starts_with('/') {
                        stripped.to_string()
                    } else {
                        format!("/{}", stripped)
                    }
                } else {
                    path.to_string()
                };

                return Some(ResolvedRoute {
                    upstream_target: upstream.target.clone(),
                    fallback_target: upstream.fallback.clone(),
                    timeout_ms: upstream.timeout_ms,
                    tls: upstream.tls,
                    unbuffered_streaming: route.unbuffered_streaming,
                    forwarded_path,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_resolution() {
        let config = ZentinelConfig::default();
        let router = Router::new(&config);

        // /api (without trailing slash) matches api upstream
        let api_bare = router.resolve("/api").unwrap();
        assert_eq!(api_bare.upstream_target, "ferrous-api:8080");

        // /api/ matches api upstream
        let api_route = router.resolve("/api/v1/commands/orders").unwrap();
        assert_eq!(api_route.upstream_target, "ferrous-api:8080");
        assert!(api_route.unbuffered_streaming);

        // /oauth2 (without trailing slash) matches iam upstream
        let oauth_bare = router.resolve("/oauth2").unwrap();
        assert_eq!(oauth_bare.upstream_target, "ferrous-iam:8443");
        assert!(oauth_bare.tls);

        // /oauth2/ matches iam upstream
        let iam_route = router.resolve("/oauth2/token").unwrap();
        assert_eq!(iam_route.upstream_target, "ferrous-iam:8443");
        assert!(iam_route.tls);

        // /auth/ matches iam upstream
        let auth_route = router.resolve("/auth/login").unwrap();
        assert_eq!(auth_route.upstream_target, "ferrous-iam:8443");

        // / matches frontend upstream
        let fe_route = router.resolve("/").unwrap();
        assert_eq!(fe_route.upstream_target, "ferrous-frontend:5173");

        let fe_asset = router.resolve("/_app/immutable/entry.js").unwrap();
        assert_eq!(fe_asset.upstream_target, "ferrous-frontend:5173");
    }
}
