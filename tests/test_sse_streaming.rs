use ferrous_reverseproxy::config::{
    RouteRule, ServerConfig, UpstreamConfig, WafConfig, ZentinelConfig,
};
use ferrous_reverseproxy::server::ZentinelServer;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Bytes, Frame};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{Receiver, channel};

struct ChannelBody {
    rx: Receiver<Frame<Bytes>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(frame)) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Spawns a mock SSE upstream producing token stream frames with simulated inter-chunk delays
async fn spawn_mock_sse_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let builder = Builder::new(TokioExecutor::new());
                    let _ = builder
                        .serve_connection_with_upgrades(
                            io,
                            service_fn(move |req: Request<hyper::body::Incoming>| async move {
                                let path = req.uri().path().to_string();

                                if path == "/api/v1/events/stream"
                                    || path.starts_with("/api/v1/benchmarks/")
                                {
                                    let (tx, rx) = channel::<Frame<Bytes>>(4);

                                    tokio::spawn(async move {
                                        let events = [
                                            "event: message\ndata: {\"seq\":1,\"message\":\"Initiating\"}\n\n",
                                            "event: message\ndata: {\"seq\":2,\"message\":\"Processing chunk\"}\n\n",
                                            "event: complete\ndata: {\"seq\":3,\"status\":\"done\"}\n\n",
                                        ];

                                        for event in events {
                                            let _ = tx.send(Frame::data(Bytes::from(event))).await;
                                            tokio::time::sleep(tokio::time::Duration::from_millis(40)).await;
                                        }
                                    });

                                    let channel_body = ChannelBody { rx };
                                    let boxed: BoxBody<Bytes, hyper::Error> =
                                        BoxBody::new(channel_body.map_err(|e| match e {}));

                                    let res = Response::builder()
                                        .status(StatusCode::OK)
                                        .header("Content-Type", "text/event-stream")
                                        .header("Cache-Control", "no-cache")
                                        .header("Connection", "keep-alive")
                                        .body(boxed)
                                        .unwrap();
                                    Ok::<_, hyper::Error>(res)
                                } else {
                                    let res = Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(BoxBody::new(
                                            http_body_util::Full::new(Bytes::from("Not Found"))
                                                .map_err(|e| match e {}),
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

    addr
}

#[tokio::test]
async fn test_unbuffered_sse_stream_pass_through() {
    let mock_upstream_addr = spawn_mock_sse_upstream().await;

    // Ephemeral ports
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
            target: format!("127.0.0.1:{}", mock_upstream_addr.port()),
            fallback: None,
            timeout_ms: 10000,
            tls: false,
        },
    );

    let routes = vec![RouteRule {
        prefix: "/api/".to_string(),
        upstream: "api".to_string(),
        strip_prefix: false,
        unbuffered_streaming: true,
    }];

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

    tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // 1. Test /api/v1/events/stream
    let events_url = format!("https://127.0.0.1:{}/api/v1/events/stream", https_port);
    let start_time = Instant::now();
    let res = client.get(&events_url).send().await.unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // Verify unbuffered streaming headers
    let headers = res.headers();
    assert_eq!(
        headers.get("Content-Type").unwrap().to_str().unwrap(),
        "text/event-stream"
    );
    assert_eq!(
        headers.get("X-Accel-Buffering").unwrap().to_str().unwrap(),
        "no"
    );
    assert_eq!(
        headers.get("Cache-Control").unwrap().to_str().unwrap(),
        "no-cache, no-transform"
    );

    let mut stream = res.bytes_stream();
    let mut chunk_count = 0;
    let mut chunk_timestamps = Vec::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.unwrap();
        if !chunk.is_empty() {
            chunk_count += 1;
            chunk_timestamps.push(Instant::now());
        }
    }

    assert_eq!(chunk_count, 3, "Expected 3 distinct SSE event chunks");

    // Verify inter-chunk timing to prove chunks were streamed progressively and not buffered
    let total_duration = start_time.elapsed();
    assert!(
        total_duration.as_millis() >= 80,
        "Total duration {:?} should reflect upstream sleeps (zero buffering)",
        total_duration
    );

    let delta1 = chunk_timestamps[1].duration_since(chunk_timestamps[0]);
    let delta2 = chunk_timestamps[2].duration_since(chunk_timestamps[1]);
    assert!(
        delta1.as_millis() >= 25,
        "Chunk 2 must arrive after delay (was {:?}), proving no chunk buffering",
        delta1
    );
    assert!(
        delta2.as_millis() >= 25,
        "Chunk 3 must arrive after delay (was {:?}), proving no chunk buffering",
        delta2
    );

    // 2. Test /api/v1/benchmarks/{run_id}/stream
    let bench_url = format!(
        "https://127.0.0.1:{}/api/v1/benchmarks/benchmark-run-42/stream",
        https_port
    );
    let bench_res = client.get(&bench_url).send().await.unwrap();
    assert_eq!(bench_res.status(), reqwest::StatusCode::OK);
    assert_eq!(
        bench_res
            .headers()
            .get("X-Accel-Buffering")
            .unwrap()
            .to_str()
            .unwrap(),
        "no"
    );
}
