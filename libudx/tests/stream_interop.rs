#![deny(clippy::all)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{create_runtime, node_script_path, random_payload, with_timeout};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn stream_interop_large() {
    let _ = tracing_subscriber::fmt::try_init();

    with_timeout(Duration::from_secs(30), async {
        run_large_transfer_test()
            .await
            .expect("large transfer interop failed");
    })
    .await;
}

async fn run_large_transfer_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("node")
        .arg(node_script_path("udx-large-transfer.js"))
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

    let runtime = create_runtime();
    let socket = runtime.create_socket().await?;
    socket.bind("127.0.0.1:0".parse::<SocketAddr>()?).await?;
    let local_addr = socket.local_addr().await?;
    let rust_port = local_addr.port();

    let payload = random_payload(1024 * 1024);
    let expected_hash = format!("{:x}", Sha256::digest(&payload));

    let handshake = serde_json::json!({
        "port": rust_port,
        "mode": "receive_and_hash",
        "expectedSize": payload.len()
    });
    writeln!(stdin, "{handshake}")?;
    drop(stdin);

    let mut stream = runtime.create_stream(node_remote_id).await?;
    let node_addr: SocketAddr = format!("127.0.0.1:{node_port}").parse()?;
    stream.connect(&socket, node_local_id, node_addr).await?;

    let mut ready_line = String::new();
    reader.read_line(&mut ready_line)?;
    let ready: serde_json::Value = serde_json::from_str(ready_line.trim())?;
    assert!(ready["ready"].as_bool().unwrap_or(false), "node not ready");

    stream.write(&payload).await?;
    stream.shutdown().await?;

    let eof = stream.read().await?;
    assert!(eof.is_none(), "expected EOF after node ends");

    let mut result_line = String::new();
    reader.read_line(&mut result_line)?;
    let result: serde_json::Value = serde_json::from_str(result_line.trim())?;

    let received_size = result["received"].as_u64().expect("missing received");
    assert_eq!(
        received_size,
        payload.len() as u64,
        "Node received wrong size"
    );

    let received_hash = result["sha256"].as_str().expect("missing sha256");
    assert_eq!(received_hash, expected_hash, "SHA256 mismatch on Node side");

    stream.destroy().await?;
    socket.close().await?;
    drop(runtime);

    let status = child.wait()?;
    assert!(status.success(), "node process exited with: {status}");
    Ok(())
}

/// `UdxAsyncStream` must pipeline writes: 32 MiB in 512 KiB `write_all`s
/// (hypercore-sized blocks) to a udx-native receiver. With stop-and-wait per
/// write this takes ~30 s on loopback; pipelined it takes a few seconds.
#[tokio::test]
async fn async_stream_interop_pipelined_writes() {
    let _ = tracing_subscriber::fmt::try_init();

    with_timeout(Duration::from_secs(60), async {
        run_pipelined_transfer_test()
            .await
            .expect("pipelined transfer interop failed");
    })
    .await;
}

async fn run_pipelined_transfer_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("node")
        .arg(node_script_path("udx-large-transfer.js"))
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

    let runtime = create_runtime();
    let socket = runtime.create_socket().await?;
    socket.bind("127.0.0.1:0".parse::<SocketAddr>()?).await?;
    let rust_port = socket.local_addr().await?.port();

    let payload = random_payload(32 * 1024 * 1024);
    let expected_hash = format!("{:x}", Sha256::digest(&payload));

    let handshake = serde_json::json!({
        "port": rust_port,
        "mode": "receive_and_hash",
        "expectedSize": payload.len()
    });
    writeln!(stdin, "{handshake}")?;
    drop(stdin);

    let stream = runtime.create_stream(node_remote_id).await?;
    let node_addr: SocketAddr = format!("127.0.0.1:{node_port}").parse()?;
    stream.connect(&socket, node_local_id, node_addr).await?;

    let mut ready_line = String::new();
    reader.read_line(&mut ready_line)?;
    let ready: serde_json::Value = serde_json::from_str(ready_line.trim())?;
    assert!(ready["ready"].as_bool().unwrap_or(false), "node not ready");

    let mut stream = stream.into_async_stream();
    let started = Instant::now();
    for block in payload.chunks(512 * 1024) {
        stream.write_all(block).await?;
    }
    stream.shutdown().await?;
    let elapsed = started.elapsed();
    let mib_per_s = payload.len() as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
    eprintln!(
        "rust -> node: {} MiB in {elapsed:?} ({mib_per_s:.1} MiB/s)",
        payload.len() >> 20
    );

    let mut result_line = String::new();
    reader.read_line(&mut result_line)?;
    let result: serde_json::Value = serde_json::from_str(result_line.trim())?;
    assert_eq!(
        result["received"].as_u64(),
        Some(payload.len() as u64),
        "Node received wrong size"
    );
    assert_eq!(
        result["sha256"].as_str(),
        Some(expected_hash.as_str()),
        "SHA256 mismatch on Node side"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "32 MiB took {elapsed:?}: writes are not pipelined"
    );

    // Node ends its side once it has hashed everything; ACK that END before
    // the processor goes away with the stream.
    let mut eof = Vec::new();
    stream.read_to_end(&mut eof).await?;
    assert!(eof.is_empty(), "Node sent unexpected data");
    drop(stream);
    socket.close().await?;
    drop(runtime);

    let status = child.wait()?;
    assert!(status.success(), "node process exited with: {status}");
    Ok(())
}

#[tokio::test]
async fn stream_interop_bidirectional() {
    let _ = tracing_subscriber::fmt::try_init();

    with_timeout(Duration::from_secs(30), async {
        run_bidirectional_interop_test()
            .await
            .expect("bidirectional interop failed");
    })
    .await;
}

async fn run_bidirectional_interop_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("node")
        .arg(node_script_path("udx-large-transfer.js"))
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

    let runtime = create_runtime();
    let socket = runtime.create_socket().await?;
    socket.bind("127.0.0.1:0".parse::<SocketAddr>()?).await?;
    let local_addr = socket.local_addr().await?;
    let rust_port = local_addr.port();

    let rust_payload = random_payload(100 * 1024);
    let rust_hash = format!("{:x}", Sha256::digest(&rust_payload));

    let node_send_size: usize = 100 * 1024;

    let handshake = serde_json::json!({
        "port": rust_port,
        "mode": "send_and_receive",
        "sendSize": node_send_size
    });
    writeln!(stdin, "{handshake}")?;
    drop(stdin);

    let mut stream = runtime.create_stream(node_remote_id).await?;
    let node_addr: SocketAddr = format!("127.0.0.1:{node_port}").parse()?;
    stream.connect(&socket, node_local_id, node_addr).await?;

    let mut ready_line = String::new();
    reader.read_line(&mut ready_line)?;
    let ready: serde_json::Value = serde_json::from_str(ready_line.trim())?;
    assert!(ready["ready"].as_bool().unwrap_or(false), "node not ready");

    stream.write(&rust_payload).await?;
    stream.shutdown().await?;

    let mut received_from_node = Vec::new();
    while let Some(chunk) = stream.read().await? {
        received_from_node.extend_from_slice(&chunk);
    }

    assert_eq!(
        received_from_node.len(),
        node_send_size,
        "received {} bytes from Node, expected {}",
        received_from_node.len(),
        node_send_size
    );

    let mut result_line = String::new();
    reader.read_line(&mut result_line)?;
    let result: serde_json::Value = serde_json::from_str(result_line.trim())?;

    let node_received = result["received"].as_u64().expect("missing received") as usize;
    assert_eq!(
        node_received,
        rust_payload.len(),
        "Node received wrong size from Rust"
    );

    let node_received_hash = result["receivedSha256"]
        .as_str()
        .expect("missing receivedSha256");
    assert_eq!(
        node_received_hash, rust_hash,
        "Node SHA256 mismatch for Rust data"
    );

    let node_sent_hash = result["sentSha256"].as_str().expect("missing sentSha256");
    let our_received_hash = format!("{:x}", Sha256::digest(&received_from_node));
    assert_eq!(
        our_received_hash, node_sent_hash,
        "Rust SHA256 mismatch for Node data"
    );

    stream.destroy().await?;
    socket.close().await?;
    drop(runtime);

    let status = child.wait()?;
    assert!(status.success(), "node process exited with: {status}");
    Ok(())
}
