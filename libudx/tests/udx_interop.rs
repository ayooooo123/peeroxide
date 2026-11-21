use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};

use libudx::UdxRuntime;

fn node_echo_server_path() -> String {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    format!("{manifest}/../tests/node/udx-echo-server.js")
}

#[tokio::test]
async fn bidirectional_echo_with_node() {
    let _ = tracing_subscriber::fmt::try_init();

    let result = tokio::time::timeout(std::time::Duration::from_secs(15), run_echo_test()).await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("test failed: {e}"),
        Err(_) => panic!("test timed out after 15s"),
    }
}

async fn run_echo_test() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("node")
        .arg(node_echo_server_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let stdout = child.stdout.take().expect("no stdout");
    let mut stdin = child.stdin.take().expect("no stdin");

    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let info: serde_json::Value = serde_json::from_str(line.trim())?;
    let node_port = info["port"].as_u64().expect("missing port") as u16;
    let node_local_id = info["localId"].as_u64().expect("missing localId") as u32;
    let node_remote_id = info["remoteId"].as_u64().expect("missing remoteId") as u32;

    let runtime = UdxRuntime::new()?;

    let socket = runtime.create_socket().await?;
    socket
        .bind("127.0.0.1:0".parse::<SocketAddr>().expect("parse addr"))
        .await?;
    let local_addr = socket.local_addr().await?;
    let rust_port = local_addr.port();

    let handshake = serde_json::json!({ "port": rust_port });
    writeln!(stdin, "{handshake}")?;
    drop(stdin);

    let mut stream = runtime.create_stream(node_remote_id).await?;

    let node_addr: SocketAddr = format!("127.0.0.1:{node_port}").parse()?;
    stream.connect(&socket, node_local_id, node_addr).await?;

    let mut ready_line = String::new();
    reader.read_line(&mut ready_line)?;
    let ready: serde_json::Value = serde_json::from_str(ready_line.trim())?;
    assert!(ready["ready"].as_bool().unwrap_or(false), "node not ready");

    let test_messages = [
        b"hello from rust".to_vec(),
        b"second message".to_vec(),
        vec![0u8; 1024],
        b"final".to_vec(),
    ];

    for msg in &test_messages {
        stream.write(msg).await?;
    }

    for expected in &test_messages {
        let echoed = stream.read().await?.expect("unexpected EOF");
        assert_eq!(&echoed, expected, "echo mismatch");
    }

    stream.shutdown().await?;

    let eof = stream.read().await?;
    assert!(eof.is_none(), "expected EOF after shutdown exchange");

    stream.destroy().await?;
    socket.close().await?;
    drop(runtime);

    let status = child.wait()?;
    assert!(status.success(), "node echo server exited with: {status}");
    Ok(())
}

/// A clean two-way end with udx-native: Rust ends first, Node ends on EOF,
/// and both streams close by themselves (C `close_stream` on
/// `UDX_STREAM_ALL_ENDED`): Rust's close observers fire while its owner
/// still holds the stream, and Node's `close` event ends the process.
#[tokio::test]
async fn clean_two_way_end_closes_both_sides_with_node() {
    let mut child = Command::new("node")
        .arg(node_echo_server_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn node");
    let mut reader = BufReader::new(child.stdout.take().expect("no stdout"));
    let mut stdin = child.stdin.take().expect("no stdin");
    let mut line = String::new();
    reader.read_line(&mut line).expect("node info");
    let info: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
    let node_port = info["port"].as_u64().expect("missing port") as u16;
    let node_local_id = info["localId"].as_u64().expect("missing localId") as u32;
    let node_remote_id = info["remoteId"].as_u64().expect("missing remoteId") as u32;

    let runtime = UdxRuntime::new().expect("runtime");
    let socket = runtime.create_socket().await.expect("socket");
    socket
        .bind("127.0.0.1:0".parse::<SocketAddr>().expect("addr"))
        .await
        .expect("bind");
    let rust_port = socket.local_addr().await.expect("local addr").port();
    writeln!(stdin, "{}", serde_json::json!({ "port": rust_port })).expect("handshake");
    drop(stdin);

    let mut stream = runtime.create_stream(node_remote_id).await.expect("stream");
    let node_addr: SocketAddr = format!("127.0.0.1:{node_port}").parse().expect("addr");
    stream
        .connect(&socket, node_local_id, node_addr)
        .await
        .expect("connect");
    line.clear();
    reader.read_line(&mut line).expect("ready");

    let abort = stream.abort_handle();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        stream.write(b"bye").await.expect("write");
        stream.shutdown().await.expect("shutdown");
        assert_eq!(
            stream.read().await.expect("echo").as_deref(),
            Some(&b"bye"[..])
        );
        assert!(stream.read().await.expect("eof").is_none());
        abort.closed().await;
    })
    .await
    .expect("the Rust stream never closed after both ends");
    assert!(!abort.is_alive());

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait node") {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "node stream never closed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(status.success(), "node echo server exited with: {status}");
    drop(stream);
}
