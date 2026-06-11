use std::time::Duration;

use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::server::config::AcceptorConfig;
use crate::server::e2e_support::{
    connect_tls, connect_tls_with_prefix, feature_context_with_auth, proxy_v2_header_ipv4,
    read_until_idle, request_response, CustomerMode, FakeCustomer, TestServerHandle,
};
use crate::server::metrics::AcceptMetrics;

/// The acceptor profiles a correctness test should hold under.
fn configs() -> Vec<AcceptorConfig> {
    vec![
        AcceptorConfig::serial_compat(),
        AcceptorConfig::concurrent_default(),
    ]
}

const IDLE: Duration = Duration::from_millis(500);

// Test 1 — happy path: one client, real TLS, GET /, customer replies, the
// client receives the response.
#[tokio::test]
#[serial]
async fn test1_happy_path_request_response() {
    for config in configs() {
        let customer = FakeCustomer::spawn(CustomerMode::HttpOk).await;
        let server = TestServerHandle::spawn(
            config,
            customer.port(),
            feature_context_with_auth(false),
            AcceptMetrics::new(),
        )
        .await;

        let response = request_response(server.addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("200"), "expected 200, got {text:?}");
        assert!(text.contains("OK"), "expected body, got {text:?}");
    }
}

// Test 2 — keep-alive: two requests on the *same* TLS connection are both served
// (guards the per-connection serve loop).
#[tokio::test]
#[serial]
async fn test2_two_requests_one_connection() {
    for config in configs() {
        let customer = FakeCustomer::spawn(CustomerMode::HttpOk).await;
        let server = TestServerHandle::spawn(
            config,
            customer.port(),
            feature_context_with_auth(false),
            AcceptMetrics::new(),
        )
        .await;

        let mut stream = connect_tls(server.addr).await;

        stream
            .write_all(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let r1 = read_until_idle(&mut stream, IDLE).await;
        assert!(
            String::from_utf8_lossy(&r1).contains("200"),
            "first response missing 200: {:?}",
            String::from_utf8_lossy(&r1)
        );

        stream
            .write_all(b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let r2 = read_until_idle(&mut stream, IDLE).await;
        assert!(
            String::from_utf8_lossy(&r2).contains("200"),
            "second response missing 200: {:?}",
            String::from_utf8_lossy(&r2)
        );
    }
}

// Test 3 — a non-HTTP request is piped raw to the customer when auth is disabled.
#[tokio::test]
#[serial]
async fn test3_non_http_piped_when_auth_disabled() {
    let customer = FakeCustomer::spawn(CustomerMode::Echo).await;
    let server = TestServerHandle::spawn(
        AcceptorConfig::serial_compat(),
        customer.port(),
        feature_context_with_auth(false),
        AcceptMetrics::new(),
    )
    .await;

    let mut stream = connect_tls(server.addr).await;
    let payload: &[u8] = b"\x00\x01\x02NON-HTTP-PAYLOAD\x03\x04";
    stream.write_all(payload).await.unwrap();

    let echoed = read_until_idle(&mut stream, IDLE).await;
    assert_eq!(
        &echoed, payload,
        "non-http bytes should be piped to the customer and echoed back"
    );
}

// Test 3b — with auth enabled, a non-HTTP request is closed (not piped).
#[tokio::test]
#[serial]
async fn test3b_non_http_rejected_when_auth_enabled() {
    let customer = FakeCustomer::spawn(CustomerMode::Echo).await;
    let server = TestServerHandle::spawn(
        AcceptorConfig::serial_compat(),
        customer.port(),
        feature_context_with_auth(true),
        AcceptMetrics::new(),
    )
    .await;

    let mut stream = connect_tls(server.addr).await;
    let payload: &[u8] = b"\x00\x01\x02NON-HTTP-PAYLOAD\x03\x04";
    stream.write_all(payload).await.unwrap();

    let response = read_until_idle(&mut stream, IDLE).await;
    assert!(
        response.is_empty(),
        "auth-enabled non-http connection should be closed without piping, got {response:?}"
    );
}

// Test 4 — a websocket upgrade is detected and piped to the customer (auth off).
#[tokio::test]
#[serial]
async fn test4_websocket_piped_when_auth_disabled() {
    let customer = FakeCustomer::spawn(CustomerMode::Echo).await;
    let server = TestServerHandle::spawn(
        AcceptorConfig::serial_compat(),
        customer.port(),
        feature_context_with_auth(false),
        AcceptMetrics::new(),
    )
    .await;

    let mut stream = connect_tls(server.addr).await;
    stream
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .await
        .unwrap();

    let echoed = read_until_idle(&mut stream, IDLE).await;
    let text = String::from_utf8_lossy(&echoed);
    assert!(
        text.contains("websocket") || text.contains("/ws"),
        "expected the websocket request to be piped to the customer, got {text:?}"
    );
}

// Test 4b — with auth enabled, a websocket upgrade without an api-key is rejected
// (not piped).
#[tokio::test]
#[serial]
async fn test4b_websocket_rejected_without_api_key() {
    let customer = FakeCustomer::spawn(CustomerMode::Echo).await;
    let server = TestServerHandle::spawn(
        AcceptorConfig::serial_compat(),
        customer.port(),
        feature_context_with_auth(true),
        AcceptMetrics::new(),
    )
    .await;

    let mut stream = connect_tls(server.addr).await;
    stream
        .write_all(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n")
        .await
        .unwrap();

    let response = read_until_idle(&mut stream, IDLE).await;
    let text = String::from_utf8_lossy(&response);
    assert!(!response.is_empty(), "expected a rejection response");
    assert!(
        !text.contains("/ws"),
        "unauthorized websocket request must not be piped, got {text:?}"
    );
}

// Test 5 — malformed / non-TLS bytes are rejected without taking down the
// server: a subsequent well-formed client still succeeds.
#[tokio::test]
#[serial]
async fn test5_malformed_tls_does_not_kill_server() {
    let customer = FakeCustomer::spawn(CustomerMode::HttpOk).await;
    let server = TestServerHandle::spawn(
        AcceptorConfig::serial_compat(),
        customer.port(),
        feature_context_with_auth(false),
        AcceptMetrics::new(),
    )
    .await;

    {
        let mut tcp = TcpStream::connect(server.addr).await.unwrap();
        let _ = tcp
            .write_all(b"this is definitely not a TLS client hello\r\n\r\n")
            .await;
        let _ = tcp.shutdown().await;
    }

    let response = request_response(server.addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(
        String::from_utf8_lossy(&response).contains("200"),
        "server should survive malformed input and serve the next client"
    );
}

// Test 6 — customer process down → clean error response, server survives.
#[tokio::test]
#[serial]
async fn test6_customer_down_clean_error_server_survives() {
    let customer = FakeCustomer::spawn(CustomerMode::Refuse).await;
    let server = TestServerHandle::spawn(
        AcceptorConfig::serial_compat(),
        customer.port(),
        feature_context_with_auth(false),
        AcceptMetrics::new(),
    )
    .await;

    let response = request_response(server.addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("500") || text.contains("message"),
        "expected a clean error response when the customer is down, got {text:?}"
    );

    // The server is still accepting + serving connections.
    let mut stream = connect_tls(server.addr).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let r2 = read_until_idle(&mut stream, IDLE).await;
    assert!(
        !r2.is_empty(),
        "server should still respond after a customer failure"
    );
}

// Test 7 — a PROXY v2 header is parsed and the recovered remote addr is forwarded
// as X-Forwarded-For.
#[tokio::test]
#[serial]
async fn test7_proxy_protocol_recovers_remote_addr() {
    for config in configs() {
        let customer = FakeCustomer::spawn(CustomerMode::ReflectRequest).await;
        let server = TestServerHandle::spawn(
            config,
            customer.port(),
            feature_context_with_auth(false),
            AcceptMetrics::new(),
        )
        .await;

        let header = proxy_v2_header_ipv4();
        let mut stream = connect_tls_with_prefix(server.addr, Some(&header)).await;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();

        let response = read_until_idle(&mut stream, IDLE).await;
        let text = String::from_utf8_lossy(&response).to_lowercase();
        assert!(
            text.contains("x-forwarded-for: 1.2.3.4"),
            "expected X-Forwarded-For: 1.2.3.4 in the reflected request, got {text:?}"
        );
    }
}

// Test 14 — end-to-end handshake timeout: a real client completes the TCP
// connect then sends nothing; with a short real `handshake_timeout` the server
// closes it and keeps serving other clients. (Real time — kept to one test.)
#[tokio::test]
#[serial]
async fn test14_end_to_end_handshake_timeout() {
    let customer = FakeCustomer::spawn(CustomerMode::HttpOk).await;
    let config = AcceptorConfig {
        max_concurrent_connections: 64,
        max_concurrent_handshakes: 64,
        handshake_timeout: Some(Duration::from_millis(200)),
    };
    let server = TestServerHandle::spawn(
        config,
        customer.port(),
        feature_context_with_auth(false),
        AcceptMetrics::new(),
    )
    .await;

    // Connect but never send a ClientHello.
    let mut stalled = TcpStream::connect(server.addr).await.unwrap();

    // A well-formed client is still served despite the stalled handshake.
    let response = request_response(server.addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(
        String::from_utf8_lossy(&response).contains("200"),
        "other clients should be served while a handshake is stalled"
    );

    // The stalled connection is closed by the server once the timeout fires.
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut buf))
        .await
        .expect("stalled connection should be closed by the handshake timeout")
        .expect("read after close");
    assert_eq!(n, 0, "server should close the stalled handshake (EOF)");
}

// Test 22 — N concurrent real clients all succeed under the concurrent profile
// (smoke test that nothing deadlocks under real load).
#[tokio::test]
#[serial]
async fn test22_many_concurrent_clients_succeed() {
    let customer = FakeCustomer::spawn(CustomerMode::HttpOk).await;
    let server = TestServerHandle::spawn(
        AcceptorConfig::concurrent_default(),
        customer.port(),
        feature_context_with_auth(false),
        AcceptMetrics::new(),
    )
    .await;
    let addr = server.addr;

    let mut clients = Vec::new();
    for _ in 0..50 {
        clients.push(tokio::spawn(async move {
            // Two sequential requests on one keep-alive connection.
            let mut stream = connect_tls(addr).await;
            for _ in 0..2 {
                stream
                    .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                    .await
                    .unwrap();
                let response = read_until_idle(&mut stream, IDLE).await;
                if !String::from_utf8_lossy(&response).contains("200") {
                    return false;
                }
            }
            true
        }));
    }

    for client in clients {
        assert!(
            client.await.unwrap(),
            "every concurrent client should succeed"
        );
    }
}

// Test 25 — a scaled-down concurrent soak on a multi-thread runtime, to flush
// out races in the shared service / cert resolver under real parallelism.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test25_concurrent_clients_multi_thread() {
    let customer = FakeCustomer::spawn(CustomerMode::HttpOk).await;
    let server = TestServerHandle::spawn(
        AcceptorConfig::concurrent_default(),
        customer.port(),
        feature_context_with_auth(false),
        AcceptMetrics::new(),
    )
    .await;
    let addr = server.addr;

    let mut clients = Vec::new();
    for _ in 0..20 {
        clients.push(tokio::spawn(async move {
            let response = request_response(addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
            String::from_utf8_lossy(&response).contains("200")
        }));
    }

    for client in clients {
        assert!(
            client.await.unwrap(),
            "every concurrent client should succeed under multi-thread"
        );
    }
}
