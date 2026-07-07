//! Local multi-process CHRONOS nettest harness.
//!
//! This is intentionally Chutney-like: it spawns local `chronosd` relay
//! processes, configures static routes via environment variables, sends a CRP7
//! packet through the chain, and verifies delivery plus ACK behavior.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use chronos_core::{
    PacketObservation, RELAY_PACKET_MAX_BYTES, RelayPacket, RelayPacketType, SecureShardBlockCodec,
    analyze_observations, derive_link_key, observations_to_csv,
};
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use tokio::time::{Duration, timeout};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = find_workspace_root()?;
    let relay1_addr = reserve_local_addr().await?;
    let relay2_addr = reserve_local_addr().await?;
    let receiver = UdpSocket::bind("127.0.0.1:0").await?;
    let receiver_addr = receiver.local_addr()?;

    println!("chronos-nettest: workspace={}", workspace.display());
    println!("chronos-nettest: relay1={relay1_addr} relay2={relay2_addr} receiver={receiver_addr}");

    let mut relay2 = spawn_chronosd(
        &workspace,
        relay2_addr,
        &format!("500={receiver_addr}"),
        "relay2",
    )?;
    let mut relay1 = spawn_chronosd(
        &workspace,
        relay1_addr,
        &format!("500={relay2_addr}"),
        "relay1",
    )?;

    // Give the child processes time to compile/start/bind when launched through cargo.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let sender = UdpSocket::bind("127.0.0.1:0").await?;
    let trace_start = now_micros()?;
    let mut trace = Vec::new();
    let packet = build_test_shard_packet()?;
    let bytes = packet
        .encode()
        .map_err(|e| format!("encode relay packet: {e:?}"))?;
    sender.send_to(&bytes, relay1_addr).await?;
    trace.push(PacketObservation {
        timestamp_micros: now_micros()?.saturating_sub(trace_start),
        length_bytes: bytes.len(),
    });

    let mut recv_buf = [0u8; RELAY_PACKET_MAX_BYTES];
    let (recv_len, _) =
        timeout(Duration::from_secs(10), receiver.recv_from(&mut recv_buf)).await??;
    trace.push(PacketObservation {
        timestamp_micros: now_micros()?.saturating_sub(trace_start),
        length_bytes: recv_len,
    });
    let received = RelayPacket::decode(&recv_buf[..recv_len])
        .map_err(|e| format!("decode received: {e:?}"))?;
    assert_eq!(received.packet_type, RelayPacketType::Shard);
    assert_eq!(received.stream_id, 500);
    assert_eq!(received.sequence, 1);
    assert_eq!(received.payload, packet.payload);

    let mut ack_buf = [0u8; RELAY_PACKET_MAX_BYTES];
    let (ack_len, _) = timeout(Duration::from_secs(10), sender.recv_from(&mut ack_buf)).await??;
    trace.push(PacketObservation {
        timestamp_micros: now_micros()?.saturating_sub(trace_start),
        length_bytes: ack_len,
    });
    let ack = RelayPacket::decode(&ack_buf[..ack_len]).map_err(|e| format!("decode ack: {e:?}"))?;
    assert_eq!(ack.packet_type, RelayPacketType::Ack);
    assert_eq!(ack.stream_id, 500);
    assert_eq!(ack.sequence, 1);

    let report = analyze_observations(&trace);
    let trace_path = write_trace(&workspace, &trace)?;
    terminate(&mut relay1).await;
    terminate(&mut relay2).await;
    println!(
        "chronos-nettest: trace={} packets={} unique_lengths={} max_jitter_us={}",
        trace_path.display(),
        report.packet_count,
        report.unique_lengths,
        report.max_interval_jitter_micros
    );
    println!("chronos-nettest: PASS sender -> relay1 -> relay2 -> receiver");
    Ok(())
}

fn now_micros() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64)
}

fn write_trace(
    workspace: &Path,
    trace: &[PacketObservation],
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = workspace.join("target").join("chronos-traces");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("nettest-{}.csv", now_micros()?));
    std::fs::write(&path, observations_to_csv(trace))?;
    Ok(path)
}

fn build_test_shard_packet() -> Result<RelayPacket, Box<dyn std::error::Error>> {
    let key =
        derive_link_key(&[0x42u8; 32], &[0x24u8; 16]).map_err(|e| format!("derive key: {e:?}"))?;
    let codec = SecureShardBlockCodec::new();
    let cells = codec
        .encode_message(&key, [0x24; 16], 1, 10, b"chronos-nettest payload")
        .map_err(|e| format!("encode message: {e:?}"))?;
    RelayPacket::shard(500, 1, &cells[0]).map_err(|e| format!("build shard packet: {e:?}").into())
}

fn spawn_chronosd(
    workspace: &Path,
    bind_addr: SocketAddr,
    static_routes: &str,
    name: &str,
) -> Result<Child, Box<dyn std::error::Error>> {
    let key_dir = workspace.join("target").join("chronos-nettest").join(name);
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace)
        .args(["run", "-p", "chronosd", "--quiet"])
        .env("CHRONOSD_UDP_RELAY_BIND", bind_addr.to_string())
        .env("CHRONOSD_STATIC_ROUTES", static_routes)
        .env("CHRONOSD_KEY_DIR", key_dir)
        .env("CHRONOSD_CONFIG", "configs/chronosd.toml")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(cmd.spawn()?)
}

async fn terminate(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn reserve_local_addr() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    Ok(socket.local_addr()?)
}

fn find_workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(root) = std::env::var("CHRONOS_WORKSPACE") {
        return Ok(PathBuf::from(root));
    }
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("crates/chronosd").exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    Err(format!(
        "could not locate CHRONOS workspace from {:?}; set CHRONOS_WORKSPACE. ts={}",
        std::env::current_dir()?,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    )
    .into())
}
