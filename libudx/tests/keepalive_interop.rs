use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use libudx::UdxRuntime;

fn node_keepalive_peer_path() -> String {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    format!("{manifest}/../tests/node/udx-keepalive-peer.js")
}

#[tokio::test]
async fn rust_keepalive_survives_idle_node_peer() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let result = tokio::time::timeout(Duration::from_secs(55), run_keepalive_test()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("test failed: {err}"),
        Err(_) => panic!("test timed out after 55s"),
    }
}

async fn run_keepalive_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("node")
        .arg(node_keepalive_peer_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdout = child.stdout.take().expect("node peer stdout unavailable");
    let mut stdin = child.stdin.take().expect("node peer stdin unavailable");
    let mut reader = BufReader::new(stdout);

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let peer: serde_json::Value = serde_json::from_str(line.trim())?;
    let node_version = peer["version"].as_str().expect("node UDX version missing");
    tracing::debug!(node_version, "Node UDX peer version");
    let node_port = peer["port"].as_u64().expect("node peer port missing") as u16;
    let node_local_id = peer["localId"]
        .as_u64()
        .expect("node peer local ID missing") as u32;
    let node_remote_id = peer["remoteId"]
        .as_u64()
        .expect("node peer remote ID missing") as u32;

    let runtime = UdxRuntime::new()?;
    let socket = runtime.create_socket().await?;
    socket.bind("127.0.0.1:0".parse::<SocketAddr>()?).await?;
    let rust_port = socket.local_addr().await?.port();

    writeln!(stdin, "{}", serde_json::json!({ "port": rust_port }))?;
    drop(stdin);

    let mut stream = runtime.create_stream(node_remote_id).await?;
    stream
        .connect(
            &socket,
            node_local_id,
            format!("127.0.0.1:{node_port}").parse::<SocketAddr>()?,
        )
        .await?;

    line.clear();
    reader.read_line(&mut line)?;
    assert!(
        serde_json::from_str::<serde_json::Value>(line.trim())?["ready"]
            .as_bool()
            .unwrap_or(false),
        "node peer was not ready"
    );

    stream.write(b"rust-first").await?;
    assert_eq!(stream.read().await?.as_deref(), Some(&b"node-first"[..]));

    tokio::time::sleep(Duration::from_secs(41)).await;
    line.clear();
    reader.read_line(&mut line)?;
    let idle: serde_json::Value = serde_json::from_str(line.trim())?;
    assert!(
        idle["idle"].as_bool().unwrap_or(false),
        "node did not finish idle period"
    );
    let packets_received = idle["packetsReceived"]
        .as_u64()
        .expect("idle receive count missing");
    let packets_transmitted = idle["packetsTransmitted"]
        .as_u64()
        .expect("idle transmit count missing");
    tracing::debug!(
        packets_received,
        packets_transmitted,
        "Node peer packet counts during Rust keepalive idle period"
    );
    assert!(
        packets_received > 0,
        "Node peer received no Rust heartbeats while idle"
    );
    assert!(
        packets_transmitted > 0,
        "Node peer did not send replies while Rust kept the stream alive"
    );

    stream.write(b"rust-second").await?;
    assert_eq!(stream.read().await?.as_deref(), Some(&b"node-second"[..]));

    stream.shutdown().await?;
    assert!(
        stream.read().await?.is_none(),
        "expected EOF after shutdown exchange"
    );
    stream.destroy().await?;
    socket.close().await?;
    drop(runtime);

    assert!(child.wait()?.success(), "node keepalive peer failed");
    Ok(())
}
