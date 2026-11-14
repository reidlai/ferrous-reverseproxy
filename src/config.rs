use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZentinelConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub waf: WafConfig,
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_https_port")]
    pub https_port: u16,
    #[serde(default)]
    pub tls: TlsConfig,
}

fn default_http_port() -> u16 {
    80
}

fn default_https_port() -> u16 {
    443
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_port: default_http_port(),
            https_port: default_https_port(),
            tls: TlsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_cert_path")]
    pub cert_path: String,
    #[serde(default = "default_key_path")]
    pub key_path: String,
    #[serde(default = "default_true")]
    pub generate_self_signed_if_missing: bool,
}

fn default_true() -> bool {
    true
}

fn default_cert_path() -> String {
    "/etc/ssl/certs/zentinel.crt".to_string()
}

fn default_key_path() -> String {
    "/etc/ssl/certs/zentinel.key".to_string()
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert_path: default_cert_path(),
            key_path: default_key_path(),
            generate_self_signed_if_missing: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rules_dir")]
    pub rules_dir: String,
    #[serde(default = "default_crs_dir")]
    pub crs_dir: String,
    #[serde(default = "default_block_mode")]
    pub block_mode: String,
}

fn default_rules_dir() -> String {
    "/etc/zentinel/rules.d".to_string()
}

fn default_crs_dir() -> String {
    "/etc/zentinel/crs".to_string()
}

fn default_block_mode() -> String {
    "block".to_string()
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_dir: default_rules_dir(),
            crs_dir: default_crs_dir(),
            block_mode: default_block_mode(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub target: String,
    #[serde(default)]
    pub fallback: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub tls: bool,
}

fn default_timeout_ms() -> u64 {
    30000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub prefix: String,
    pub upstream: String,
    #[serde(default)]
    pub strip_prefix: bool,
    #[serde(default)]
    pub unbuffered_streaming: bool,
}

impl Default for ZentinelConfig {
    fn default() -> Self {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "frontend".to_string(),
            UpstreamConfig {
                target: "ferrous-frontend:5173".to_string(),
                fallback: Some("127.0.0.1:5173".to_string()),
                timeout_ms: 30000,
                tls: false,
            },
        );
        upstreams.insert(
            "api".to_string(),
            UpstreamConfig {
                target: "ferrous-api:8080".to_string(),
                fallback: Some("127.0.0.1:8080".to_string()),
                timeout_ms: 60000,
                tls: false,
            },
        );
        upstreams.insert(
            "iam".to_string(),
            UpstreamConfig {
                target: "ferrous-iam:8443".to_string(),
                fallback: Some("127.0.0.1:8443".to_string()),
                timeout_ms: 30000,
                tls: true,
            },
        );
        upstreams.insert(
            "agent".to_string(),
            UpstreamConfig {
                target: "ferrous-agent:8081".to_string(),
                fallback: Some("127.0.0.1:8081".to_string()),
                timeout_ms: 120000,
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
                prefix: "/oauth2/".to_string(),
                upstream: "iam".to_string(),
                strip_prefix: false,
                unbuffered_streaming: false,
            },
            RouteRule {
                prefix: "/auth/".to_string(),
                upstream: "iam".to_string(),
                strip_prefix: false,
                unbuffered_streaming: false,
            },
            RouteRule {
                prefix: "/idp/".to_string(),
                upstream: "iam".to_string(),
                strip_prefix: false,
                unbuffered_streaming: false,
            },
            RouteRule {
                prefix: "/v1/chat/".to_string(),
                upstream: "agent".to_string(),
                strip_prefix: false,
                unbuffered_streaming: true,
            },
            RouteRule {
                prefix: "/".to_string(),
                upstream: "frontend".to_string(),
                strip_prefix: false,
                unbuffered_streaming: false,
            },
        ];

        Self {
            server: ServerConfig::default(),
            waf: WafConfig::default(),
            upstreams,
            routes,
        }
    }
}

impl ZentinelConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        match Self::load_from_file(path.as_ref()) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(
                    "Failed to load config from {}: {}. Falling back to default configuration.",
                    path.as_ref().display(),
                    e
                );
                Self::default()
            }
        }
    }
}
