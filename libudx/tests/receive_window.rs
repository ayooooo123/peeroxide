#![deny(clippy::all)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::proxy::{ProxyConfig, UdpProxy};
use common::{
    create_bound_socket, create_lossy_pair, create_runtime, node_script_path, random_payload,
    verify_payload, with_timeout,
};
use libudx::{UdxAsyncStream, UdxStream};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

/// The largest window of the protocol.
const WINDOW: u64 = 4 * 1024 * 1024;
const TOTAL: usize = 16 * 1024 * 1024;
const PAUSE: Duration = Duration::from_secs(2);
/// More than one window: the reader can get this far only with data that
/// the sender sent after the reader started again.
const RESUME_MARK: usize = 5 * 1024 * 1024;

/// The two read APIs of the crate, so the reader steps live in one place.
enum Reader {
    Stream(UdxStream),
    Async(UdxAsyncStream),
}

impl Reader {
    fn sync(stream: UdxStream) -> Self {
        Reader::Stream(stream)
    }

    fn async_io(stream: UdxStream) -> Self {
        Reader::Async(stream.into_async_stream())
    }

    /// The next chunk, or `None` once the peer ended the stream.
    async fn read_chunk(&mut self) -> Option<Vec<u8>> {
        match self {
            Reader::Stream(stream) => stream.read().await.expect("read"),
            Reader::Async(stream) => {
                let mut buf = vec![0u8; 65_536];
                let n = stream.read(&mut buf).await.expect("read");
                if n == 0 {
                    None
                } else {
                    buf.truncate(n);
                    Some(buf)
                }
            }
        }
    }

    /// The synchronous stream, so a test can end its own side.
    fn stream(self) -> UdxStream {
        match self {
            Reader::Stream(stream) => stream,
            Reader::Async(_) => panic!("async reader in a synchronous test"),
        }
    }
}

/// Catches a sender that keeps flooding a closed window, and a stream that
/// stays stopped after the reader resumes because no window update is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_that_stops_stops_the_sender_and_a_read_starts_it_again() {
    let _ = tracing_subscriber::fmt::try_init();
    with_timeout(
        Duration::from_secs(40),
        reader_that_stops_stops_the_sender(Reader::sync),
    )
    .await;
}

/// Catches the async reader not counting the bytes that it copied, which
/// would leave the window closed after the reader resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_async_reader_that_stops_stops_the_sender_and_a_read_starts_it_again() {
    let _ = tracing_subscriber::fmt::try_init();
    with_timeout(
        Duration::from_secs(40),
        reader_that_stops_stops_the_sender(Reader::async_io),
    )
    .await;
}

/// Catches a window update that only two Rust peers understand, and a stock
/// sender that ignores the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stock_js_sender_stops_and_starts_again() {
    let _ = tracing_subscriber::fmt::try_init();
    with_timeout(Duration::from_secs(40), async {
        run_stock_js_sender_test()
            .await
            .expect("stock JS sender interop failed");
    })
    .await;
}

/// One transfer per reader kind: the sender fills the window while the reader
/// waits, then the reader drains past the resume mark and the payload is
/// checked.
async fn reader_that_stops_stops_the_sender(make_reader: fn(UdxStream) -> Reader) {
    let runtime = create_runtime();
    let (stream_a, stream_b, _socket_a, _socket_b, proxy) =
        create_lossy_pair(&runtime, ProxyConfig::default()).await;

    let payload = random_payload(TOTAL);
    let payload_clone = payload.clone();
    let writer = tokio::spawn(async move {
        stream_a.write(&payload_clone).await.expect("write payload");
        stream_a.shutdown().await.expect("shutdown");
    });

    let mut reader = make_reader(stream_b);
    let received = stalled_sender_and_resume(&mut reader, &proxy).await;
    verify_payload(&payload, &received);
    writer.await.expect("writer task failed");
}

/// The steps shared by the three tests: the pause, the two bounds on what the
/// sender forwarded, the probe check, and the read past the resume mark.
async fn stalled_sender_and_resume(reader: &mut Reader, proxy: &UdpProxy) -> Vec<u8> {
    tokio::time::sleep(PAUSE).await;

    let stalled = proxy.forwarded_a_to_b();
    assert!(
        stalled >= WINDOW / 2,
        "the transfer did not start: {stalled} bytes forwarded"
    );
    assert!(
        stalled <= WINDOW + WINDOW / 2,
        "the sender did not stop for the closed window: {stalled} bytes forwarded"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let grown = proxy.forwarded_a_to_b() - stalled;
    assert!(
        grown <= 65_536,
        "the sender still sends data into the closed window; only small probes are right: {grown} bytes"
    );

    // The first window is already at the reader, so reaching past the resume
    // mark needs data that the sender sent after the reader started again.
    let start = Instant::now();
    let mut received = Vec::with_capacity(TOTAL);
    while received.len() < RESUME_MARK {
        let chunk = reader
            .read_chunk()
            .await
            .expect("the stream ended before the resume mark");
        received.extend_from_slice(&chunk);
    }
    let resume = start.elapsed();
    assert!(
        resume < Duration::from_millis(500),
        "new data came only after the sender's probe timer; the window update is missing: {resume:?}"
    );

    while let Some(chunk) = reader.read_chunk().await {
        received.extend_from_slice(&chunk);
    }
    received
}

/// Test 3: a stock `udx-native` sender behind the proxy, a Rust reader.
async fn run_stock_js_sender_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("node")
        .arg(node_script_path("udx-large-transfer.js"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let stdout = child.stdout.take().expect("no stdout");
    let mut stdin = child.stdin.take().expect("no stdin");

    let mut output = BufReader::new(stdout);
    let mut line = String::new();
    output.read_line(&mut line)?;
    let info: serde_json::Value = serde_json::from_str(line.trim())?;
    let node_port = info["port"].as_u64().expect("missing port") as u16;
    let node_local_id = info["localId"].as_u64().expect("missing localId") as u32;
    let node_remote_id = info["remoteId"].as_u64().expect("missing remoteId") as u32;
    let node_addr: SocketAddr = format!("127.0.0.1:{node_port}").parse()?;

    let runtime = create_runtime();
    let (socket, rust_addr) = create_bound_socket(&runtime).await;
    let proxy = UdpProxy::start(node_addr, rust_addr, ProxyConfig::default()).await;

    let handshake = serde_json::json!({
        "port": proxy.addr_for_a.port(),
        "mode": "send_and_receive",
        "sendSize": TOTAL,
    });
    writeln!(stdin, "{handshake}")?;
    drop(stdin);

    let stream = runtime.create_stream(node_remote_id).await?;
    stream
        .connect(&socket, node_local_id, proxy.addr_for_b)
        .await?;

    let mut ready_line = String::new();
    output.read_line(&mut ready_line)?;
    let ready: serde_json::Value = serde_json::from_str(ready_line.trim())?;
    assert!(ready["ready"].as_bool().unwrap_or(false), "node not ready");

    let mut incoming = Reader::Stream(stream);
    let received = stalled_sender_and_resume(&mut incoming, &proxy).await;
    assert_eq!(
        received.len(),
        TOTAL,
        "the Rust reader received the wrong size"
    );
    let received_hash = format!("{:x}", Sha256::digest(&received));

    let stream = incoming.stream();
    stream.shutdown().await?;

    let mut result_line = String::new();
    output.read_line(&mut result_line)?;
    let result: serde_json::Value = serde_json::from_str(result_line.trim())?;
    assert_eq!(
        result["sent"].as_u64(),
        Some(TOTAL as u64),
        "node sent the wrong size"
    );
    let sent_hash = result["sentSha256"].as_str().expect("missing sentSha256");
    assert_eq!(sent_hash, received_hash, "SHA256 mismatch on the Rust side");

    stream.destroy().await?;
    socket.close().await?;
    drop(runtime);

    let status = child.wait()?;
    assert!(status.success(), "node process exited with: {status}");
    Ok(())
}
