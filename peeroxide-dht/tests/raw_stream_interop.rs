//! Raw UDX stream interoperability with HyperDHT's createRawStream.

use std::time::Duration;

use libudx::UdxRuntime;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn js_raw_stream_echoes_rust_data() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let runtime = UdxRuntime::new().expect("runtime");
        let socket = runtime.create_socket().await.expect("socket");
        socket.bind("127.0.0.1:0".parse().unwrap()).await.expect("bind");
        let port = socket.local_addr().await.expect("address").port();
        let script = format!("{}/../tests/node/raw-stream-peer.js", env!("CARGO_MANIFEST_DIR"));
        let mut child = tokio::process::Command::new("node")
            .arg(script)
            .arg(port.to_string())
            .arg("23")
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start JS peer");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .await
            .expect("read JS address");
        let info: serde_json::Value = serde_json::from_str(&line).expect("JS address");
        let id = info["id"].as_u64().expect("stream id") as u32;
        let remote_port = info["port"].as_u64().expect("port") as u16;
        let mut stream = runtime.create_stream(23).await.expect("stream");
        stream.connect(&socket, id, ([127, 0, 0, 1], remote_port).into()).await.expect("connect");
        stream.write(b"raw-stream-interop").await.expect("write");
        assert_eq!(stream.read().await.expect("read").expect("data"), b"raw-stream-interop");
        stream.destroy().await.expect("destroy stream");
        child.kill().await.expect("stop JS peer");
    })
    .await
    .expect("raw stream interop timed out");
}
