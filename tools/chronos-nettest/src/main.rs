#![deny(unsafe_code)]
//! Local CHRONOS relay experiment harness.
//!
//! Scenario reports are derived from actual localhost UDP execution and signed
//! directory-record validation. They are local prototype measurements, not
//! anonymity or deployment claims.

use std::error::Error;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use chronos_core::anonymity_metrics::{
    compare_fec_overhead, mutual_information_timing, simulate_adaptive_mix, sweep_mix_k_latency_csv,
};
use chronos_core::fountain::encode_payload_with_repair;
use chronos_core::mix_policy::MixProfile;
use chronos_core::{
    NodeKeyMaterial, RELAY_PACKET_MAX_BYTES, RelayPacket, RelayPacketType, RouteCommand,
    RouteHopSecret, RoutePacketBuilder,
};
use chronos_dir::api::{DirectoryApiConfig, DirectoryApiError, handle_command};
use chronos_dir::signed_record::sign_record;
use chronos_dir::store::{DirectoryStore, RelayRecord};
use chronosd::udp_relay::{ChronosUdpRelay, StaticRouteTable, UdpRelayError};
use serde::Serialize;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

const STREAM_1: u64 = 10_001;
const STREAM_2: u64 = 10_002;
const STREAM_3: u64 = 10_003;
const ROUTE_SEQUENCE: u64 = 1;
const DIRECTORY_LIFETIME_SECONDS: u64 = 300;
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(2);
const NO_SECOND_DELIVERY_TIMEOUT: Duration = Duration::from_millis(200);
const THREE_HOP_PAYLOAD: &[u8] = b"chronos-nettest three-hop payload";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    ThreeHopLocal,
    ReplayNegative,
    DirectoryNegative,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "three-hop-local" => Ok(Self::ThreeHopLocal),
            "replay-negative" => Ok(Self::ReplayNegative),
            "directory-negative" => Ok(Self::DirectoryNegative),
            other => Err(format!(
                "invalid scenario {other:?}; expected three-hop-local|replay-negative|directory-negative"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    scenario: Option<Scenario>,
    out: Option<PathBuf>,
    messages: usize,
}

fn parse_cli<I>(args: I) -> Result<Cli, String>
where
    I: IntoIterator<Item = String>,
{
    let mut scenario = None;
    let mut out = None;
    let mut messages = 1usize;
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--scenario" => {
                let value = args
                    .next()
                    .ok_or("--scenario requires a scenario name".to_string())?;
                if scenario.is_some() {
                    return Err("--scenario may be specified only once".to_string());
                }
                scenario = Some(Scenario::parse(&value)?);
            }
            "--out" => {
                let value = args.next().ok_or("--out requires a path".to_string())?;
                if out.is_some() {
                    return Err("--out may be specified only once".to_string());
                }
                out = Some(PathBuf::from(value));
            }
            "--messages" => {
                let value = args
                    .next()
                    .ok_or("--messages requires a positive integer".to_string())?;
                messages = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --messages value {value:?}"))?;
                if messages == 0 {
                    return Err("--messages must be at least 1".to_string());
                }
            }
            "--help" | "-h" => {
                return Err(
                    "usage: chronos-nettest --scenario <three-hop-local|replay-negative|directory-negative> [--out <path>] [--messages <n>]"
                        .to_string(),
                )
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if scenario.is_none() && out.is_some() {
        return Err("--out requires --scenario".to_string());
    }
    Ok(Cli {
        scenario,
        out,
        messages,
    })
}

trait ScenarioStatus {
    fn is_ok(&self) -> bool;
}

#[derive(Debug, Serialize)]
struct ThreeHopReport {
    scenario: &'static str,
    ok: bool,
    relays: usize,
    messages_sent: usize,
    messages_delivered: usize,
    replays_attempted: usize,
    replays_rejected: usize,
    payload_bytes: usize,
    packet_size_bytes: usize,
    latency_ms: f64,
    relay_bindings: Vec<String>,
    directory_records_inserted: usize,
    errors: Vec<String>,
}

impl ScenarioStatus for ThreeHopReport {
    fn is_ok(&self) -> bool {
        self.ok
    }
}

#[derive(Debug, Serialize)]
struct ReplayReport {
    scenario: &'static str,
    ok: bool,
    relays: usize,
    messages_sent: usize,
    messages_delivered: usize,
    replays_attempted: usize,
    replays_rejected: usize,
    first_delivery_ok: bool,
    replay_rejected: bool,
    replay_error: Option<String>,
    errors: Vec<String>,
}

impl ScenarioStatus for ReplayReport {
    fn is_ok(&self) -> bool {
        self.ok
    }
}

#[derive(Debug, Serialize)]
struct DirectoryNegativeCase {
    name: &'static str,
    ok: bool,
    observed_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct DirectoryNegativeReport {
    scenario: &'static str,
    ok: bool,
    cases: Vec<DirectoryNegativeCase>,
    errors: Vec<String>,
}

impl ScenarioStatus for DirectoryNegativeReport {
    fn is_ok(&self) -> bool {
        self.ok
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = parse_cli(std::env::args().skip(1)).map_err(|error| {
        eprintln!("chronos-nettest: {error}");
        error
    })?;

    if let Some(scenario) = cli.scenario {
        match scenario {
            Scenario::ThreeHopLocal => {
                let report = run_three_hop_local(cli.messages).await;
                finish_report(&report, cli.out)?;
            }
            Scenario::ReplayNegative => {
                let report = run_replay_negative(cli.messages).await;
                finish_report(&report, cli.out)?;
            }
            Scenario::DirectoryNegative => {
                let report = run_directory_negative(cli.messages).await;
                finish_report(&report, cli.out)?;
            }
        }
        return Ok(());
    }

    run_legacy_mode()
}

fn finish_report<T>(report: &T, out: Option<PathBuf>) -> Result<(), Box<dyn Error>>
where
    T: Serialize + ScenarioStatus,
{
    let json = serde_json::to_string_pretty(report)?;
    if let Some(path) = out {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, format!("{json}\n"))?;
    } else {
        println!("{json}");
    }
    if report.is_ok() {
        Ok(())
    } else {
        Err("scenario assertions failed; see JSON report errors".into())
    }
}

async fn run_three_hop_local(messages: usize) -> ThreeHopReport {
    let mut report = ThreeHopReport {
        scenario: "three-hop-local",
        ok: false,
        relays: 3,
        messages_sent: 0,
        messages_delivered: 0,
        replays_attempted: 0,
        replays_rejected: 0,
        payload_bytes: THREE_HOP_PAYLOAD.len(),
        packet_size_bytes: 0,
        latency_ms: 0.0,
        relay_bindings: Vec::new(),
        directory_records_inserted: 0,
        errors: Vec::new(),
    };
    if messages != 1 {
        report.errors.push(
            "three-hop-local currently supports --messages 1; multiple route packets require a persistent sender session"
                .to_string(),
        );
        return report;
    }

    match execute_three_hop_local().await {
        Ok(execution) => {
            report.messages_sent = 1;
            report.messages_delivered = 1;
            report.packet_size_bytes = execution.packet_size_bytes;
            report.latency_ms = execution.latency_ms;
            report.relay_bindings = execution.relay_bindings;
            report.directory_records_inserted = execution.directory_records_inserted;
            report.ok = true;
        }
        Err(error) => report.errors.push(error),
    }
    report
}

struct ThreeHopExecution {
    packet_size_bytes: usize,
    latency_ms: f64,
    relay_bindings: Vec<String>,
    directory_records_inserted: usize,
}

async fn execute_three_hop_local() -> Result<ThreeHopExecution, String> {
    let now_unix = unix_now();
    let receiver = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("bind receiver: {error}"))?;
    let receiver_addr = receiver
        .local_addr()
        .map_err(|error| format!("receiver address: {error}"))?;

    let mut directory = DirectoryStore::new();
    let relay_1_keys =
        NodeKeyMaterial::generate().map_err(|error| format!("relay 1 keys: {error:?}"))?;
    let relay_2_keys =
        NodeKeyMaterial::generate().map_err(|error| format!("relay 2 keys: {error:?}"))?;
    let relay_3_keys =
        NodeKeyMaterial::generate().map_err(|error| format!("relay 3 keys: {error:?}"))?;

    let hop_1 = RouteHopSecret([0x11; 32]);
    let hop_2 = RouteHopSecret([0x22; 32]);
    let hop_3 = RouteHopSecret([0x33; 32]);

    let mut relay_3_routes = StaticRouteTable::new();
    relay_3_routes.insert(STREAM_3, receiver_addr);
    let mut relay_3 = ChronosUdpRelay::bind("127.0.0.1:0", relay_3_routes)
        .await
        .map_err(display_relay_error("bind relay 3"))?;
    relay_3.insert_route_secret(STREAM_3, hop_3.clone());
    let relay_3_addr = relay_3
        .local_addr()
        .map_err(display_relay_error("relay 3 address"))?;
    insert_signed_relay_record(
        &mut directory,
        "relay-3",
        relay_3_addr,
        &relay_3_keys,
        now_unix,
    )?;

    let relay_3_directory_addr = directory
        .get("relay-3", now_unix)
        .ok_or("directory lookup for relay-3 failed")?
        .address;
    let mut relay_2_routes = StaticRouteTable::new();
    relay_2_routes.insert(STREAM_3, relay_3_directory_addr);
    let mut relay_2 = ChronosUdpRelay::bind("127.0.0.1:0", relay_2_routes)
        .await
        .map_err(display_relay_error("bind relay 2"))?;
    relay_2.insert_route_secret(STREAM_2, hop_2.clone());
    let relay_2_addr = relay_2
        .local_addr()
        .map_err(display_relay_error("relay 2 address"))?;
    insert_signed_relay_record(
        &mut directory,
        "relay-2",
        relay_2_addr,
        &relay_2_keys,
        now_unix,
    )?;

    let relay_2_directory_addr = directory
        .get("relay-2", now_unix)
        .ok_or("directory lookup for relay-2 failed")?
        .address;
    let mut relay_1_routes = StaticRouteTable::new();
    relay_1_routes.insert(STREAM_2, relay_2_directory_addr);
    let mut relay_1 = ChronosUdpRelay::bind("127.0.0.1:0", relay_1_routes)
        .await
        .map_err(display_relay_error("bind relay 1"))?;
    relay_1.insert_route_secret(STREAM_1, hop_1.clone());
    let relay_1_addr = relay_1
        .local_addr()
        .map_err(display_relay_error("relay 1 address"))?;
    insert_signed_relay_record(
        &mut directory,
        "relay-1",
        relay_1_addr,
        &relay_1_keys,
        now_unix,
    )?;

    // Retrieve all three authenticated records before route construction. The
    // addresses used above therefore come from the signed directory store.
    for node_id in ["relay-1", "relay-2", "relay-3"] {
        directory
            .get_signed(node_id, now_unix)
            .ok_or_else(|| format!("signed directory lookup failed for {node_id}"))?;
    }

    let route = RoutePacketBuilder::new(
        vec![hop_1, hop_2, hop_3],
        vec![
            RouteCommand::forward(STREAM_2),
            RouteCommand::forward(STREAM_3),
            RouteCommand::deliver_local(),
        ],
    )
    .build(THREE_HOP_PAYLOAD)
    .map_err(|error| format!("build route: {error:?}"))?;
    let relay_packet = RelayPacket::route(STREAM_1, ROUTE_SEQUENCE, &route)
        .map_err(|error| format!("encode relay route: {error:?}"))?;
    let packet_bytes = relay_packet
        .encode()
        .map_err(|error| format!("serialize relay route: {error:?}"))?;

    let sender = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("bind sender: {error}"))?;
    let relay_3_task = tokio::spawn(async move { relay_3.relay_one().await });
    let relay_2_task = tokio::spawn(async move { relay_2.relay_one().await });
    let relay_1_task = tokio::spawn(async move { relay_1.relay_one().await });

    let started = Instant::now();
    sender
        .send_to(&packet_bytes, relay_1_addr)
        .await
        .map_err(|error| format!("send route to relay 1: {error}"))?;

    let mut receiver_buffer = [0u8; RELAY_PACKET_MAX_BYTES];
    let (received_len, _) = timeout(SCENARIO_TIMEOUT, receiver.recv_from(&mut receiver_buffer))
        .await
        .map_err(|_| "timed out waiting for receiver delivery".to_string())?
        .map_err(|error| format!("receive delivered payload: {error}"))?;
    let delivered = RelayPacket::decode(&receiver_buffer[..received_len])
        .map_err(|error| format!("decode delivered packet: {error:?}"))?;
    if delivered.packet_type != RelayPacketType::Data {
        return Err(format!(
            "receiver got {:?}, expected data",
            delivered.packet_type
        ));
    }
    if delivered.payload != THREE_HOP_PAYLOAD {
        return Err("receiver payload did not match the sent bytes".to_string());
    }

    let mut ack_buffer = [0u8; RELAY_PACKET_MAX_BYTES];
    let (ack_len, _) = timeout(SCENARIO_TIMEOUT, sender.recv_from(&mut ack_buffer))
        .await
        .map_err(|_| "timed out waiting for sender acknowledgement".to_string())?
        .map_err(|error| format!("receive sender acknowledgement: {error}"))?;
    let acknowledgement = RelayPacket::decode(&ack_buffer[..ack_len])
        .map_err(|error| format!("decode sender acknowledgement: {error:?}"))?;
    if acknowledgement.packet_type != RelayPacketType::Ack
        || acknowledgement.stream_id != STREAM_1
        || acknowledgement.sequence != ROUTE_SEQUENCE
    {
        return Err("sender did not receive the expected relay acknowledgement".to_string());
    }

    for (name, task) in [
        ("relay-1", relay_1_task),
        ("relay-2", relay_2_task),
        ("relay-3", relay_3_task),
    ] {
        let result = timeout(SCENARIO_TIMEOUT, task)
            .await
            .map_err(|_| format!("{name} did not finish"))?
            .map_err(|error| format!("{name} task join: {error}"))?;
        result.map_err(|error| format!("{name} processing failed: {error:?}"))?;
    }

    Ok(ThreeHopExecution {
        packet_size_bytes: packet_bytes.len(),
        latency_ms: started.elapsed().as_secs_f64() * 1_000.0,
        relay_bindings: vec![
            relay_1_addr.to_string(),
            relay_2_addr.to_string(),
            relay_3_addr.to_string(),
        ],
        directory_records_inserted: directory.len(),
    })
}

async fn run_replay_negative(messages: usize) -> ReplayReport {
    let mut report = ReplayReport {
        scenario: "replay-negative",
        ok: false,
        relays: 1,
        messages_sent: 0,
        messages_delivered: 0,
        replays_attempted: 0,
        replays_rejected: 0,
        first_delivery_ok: false,
        replay_rejected: false,
        replay_error: None,
        errors: Vec::new(),
    };
    if messages != 1 {
        report.errors.push(
            "replay-negative currently supports --messages 1; it always sends one original and one replay"
                .to_string(),
        );
        return report;
    }

    match execute_replay_negative().await {
        Ok(replay_error) => {
            report.ok = true;
            report.messages_sent = 2;
            report.messages_delivered = 1;
            report.replays_attempted = 1;
            report.replays_rejected = 1;
            report.first_delivery_ok = true;
            report.replay_rejected = true;
            report.replay_error = Some(replay_error);
        }
        Err(error) => report.errors.push(error),
    }
    report
}

async fn execute_replay_negative() -> Result<String, String> {
    let receiver = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("bind receiver: {error}"))?;
    let receiver_addr = receiver
        .local_addr()
        .map_err(|error| format!("receiver address: {error}"))?;
    let replay_secret = RouteHopSecret([0x44; 32]);
    let mut routes = StaticRouteTable::new();
    routes.insert(STREAM_1, receiver_addr);
    let mut relay = ChronosUdpRelay::bind("127.0.0.1:0", routes)
        .await
        .map_err(display_relay_error("bind replay relay"))?;
    relay.insert_route_secret(STREAM_1, replay_secret.clone());
    let relay_addr = relay
        .local_addr()
        .map_err(display_relay_error("replay relay address"))?;

    let route = RoutePacketBuilder::new(vec![replay_secret], vec![RouteCommand::deliver_local()])
        .build(b"chronos-nettest replay payload")
        .map_err(|error| format!("build replay route: {error:?}"))?;
    let first = RelayPacket::route(STREAM_1, ROUTE_SEQUENCE, &route)
        .map_err(|error| format!("build first replay envelope: {error:?}"))?;
    let replay = RelayPacket::route(STREAM_1, ROUTE_SEQUENCE + 1, &route)
        .map_err(|error| format!("build replay envelope: {error:?}"))?;
    let first_bytes = first
        .encode()
        .map_err(|error| format!("encode first packet: {error:?}"))?;
    let replay_bytes = replay
        .encode()
        .map_err(|error| format!("encode replay packet: {error:?}"))?;

    let sender = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("bind sender: {error}"))?;
    sender
        .send_to(&first_bytes, relay_addr)
        .await
        .map_err(|error| format!("send first packet: {error}"))?;
    relay
        .relay_one()
        .await
        .map_err(|error| format!("first relay processing: {error:?}"))?;

    let mut receiver_buffer = [0u8; RELAY_PACKET_MAX_BYTES];
    let (received_len, _) = timeout(SCENARIO_TIMEOUT, receiver.recv_from(&mut receiver_buffer))
        .await
        .map_err(|_| "timed out waiting for first delivery".to_string())?
        .map_err(|error| format!("receive first delivery: {error}"))?;
    let delivered = RelayPacket::decode(&receiver_buffer[..received_len])
        .map_err(|error| format!("decode first delivery: {error:?}"))?;
    if delivered.packet_type != RelayPacketType::Data
        || delivered.payload != b"chronos-nettest replay payload"
    {
        return Err("first packet was not delivered unchanged".to_string());
    }

    let mut acknowledgement = [0u8; RELAY_PACKET_MAX_BYTES];
    timeout(SCENARIO_TIMEOUT, sender.recv_from(&mut acknowledgement))
        .await
        .map_err(|_| "timed out waiting for first acknowledgement".to_string())?
        .map_err(|error| format!("receive first acknowledgement: {error}"))?;

    // The inner route packet is byte-for-byte identical; only the outer relay
    // sequence changes so the outer relay sequence guard does not hide the
    // route-layer replay result.
    sender
        .send_to(&replay_bytes, relay_addr)
        .await
        .map_err(|error| format!("send replay packet: {error}"))?;
    let replay_error = relay
        .relay_one()
        .await
        .expect_err("identical route packet must be rejected by route replay state");
    if !matches!(
        replay_error,
        UdpRelayError::Route(chronos_core::RouteLayerError::Replay { .. })
            | UdpRelayError::Handler(chronos_core::RelayHandlerError::Route(
                chronos_core::RouteLayerError::Replay { .. }
            ))
    ) {
        return Err(format!("unexpected replay rejection: {replay_error:?}"));
    }

    let mut no_delivery_buffer = [0u8; RELAY_PACKET_MAX_BYTES];
    match timeout(
        NO_SECOND_DELIVERY_TIMEOUT,
        receiver.recv_from(&mut no_delivery_buffer),
    )
    .await
    {
        Err(_) => {}
        Ok(Ok(_)) => return Err("receiver got a second delivery after replay".to_string()),
        Ok(Err(error)) => return Err(format!("receiver error while checking replay: {error}")),
    }

    Ok(format!("{replay_error:?}"))
}

async fn run_directory_negative(messages: usize) -> DirectoryNegativeReport {
    let mut report = DirectoryNegativeReport {
        scenario: "directory-negative",
        ok: false,
        cases: Vec::new(),
        errors: Vec::new(),
    };
    if messages != 1 {
        report.errors.push(
            "directory-negative currently supports --messages 1 because it executes a fixed validation matrix"
                .to_string(),
        );
        return report;
    }

    let now_unix = unix_now();
    let config = DirectoryApiConfig::default();
    let mut store = DirectoryStore::new();
    let keys = match NodeKeyMaterial::generate() {
        Ok(keys) => keys,
        Err(error) => {
            report
                .errors
                .push(format!("generate directory test key: {error:?}"));
            return report;
        }
    };
    let address: SocketAddr = "127.0.0.1:7000".parse().expect("literal socket address");
    let valid = signed_record_for("negative-relay", address, &keys, now_unix + 60);

    report.cases.push(directory_case(
        "unsigned_upsert_rejected",
        handle_command(
            &mut store,
            "UPSERT negative-relay 127.0.0.1:7000 1",
            &config,
            now_unix,
        ),
        DirectoryApiError::MutationDisabled,
    ));

    let mut bad_signature = valid.clone();
    bad_signature.signature[0] ^= 1;
    report.cases.push(directory_case(
        "bad_signature_rejected",
        handle_command(
            &mut store,
            &directory_upsert_command(&bad_signature),
            &config,
            now_unix,
        ),
        DirectoryApiError::InvalidSignedRecord,
    ));

    let mut zero_record = valid.record.clone();
    zero_record.x25519_public = [0; 32];
    let zero_signed = sign_record(zero_record, "negative-relay", &keys.identity_signing);
    report.cases.push(directory_case(
        "zero_key_material_rejected",
        handle_command(
            &mut store,
            &directory_upsert_command(&zero_signed),
            &config,
            now_unix,
        ),
        DirectoryApiError::InvalidSignedRecord,
    ));

    let expired = signed_record_for("negative-relay", address, &keys, now_unix);
    report.cases.push(directory_case(
        "expired_record_rejected",
        handle_command(
            &mut store,
            &directory_upsert_command(&expired),
            &config,
            now_unix,
        ),
        DirectoryApiError::InvalidSignedRecord,
    ));

    report.ok = report.cases.iter().all(|case| case.ok);
    if !report.ok {
        report
            .errors
            .push("one or more negative directory cases were accepted unexpectedly".to_string());
    }
    report
}

fn directory_case(
    name: &'static str,
    observed: Result<String, DirectoryApiError>,
    expected: DirectoryApiError,
) -> DirectoryNegativeCase {
    match observed {
        Err(error) => DirectoryNegativeCase {
            name,
            ok: error == expected,
            observed_error: Some(format!("{error:?}")),
        },
        Ok(response) => DirectoryNegativeCase {
            name,
            ok: false,
            observed_error: Some(format!("accepted: {}", response.trim_end())),
        },
    }
}

fn insert_signed_relay_record(
    directory: &mut DirectoryStore,
    node_id: &str,
    address: SocketAddr,
    keys: &NodeKeyMaterial,
    now_unix: u64,
) -> Result<(), String> {
    let signed = signed_record_for(
        node_id,
        address,
        keys,
        now_unix + DIRECTORY_LIFETIME_SECONDS,
    );
    directory
        .upsert_signed(signed, now_unix, DIRECTORY_LIFETIME_SECONDS)
        .map_err(|error| format!("directory insert for {node_id}: {error:?}"))
}

fn signed_record_for(
    node_id: &str,
    address: SocketAddr,
    keys: &NodeKeyMaterial,
    expires_at_unix: u64,
) -> chronos_dir::signed_record::SignedRelayRecord {
    sign_record(
        RelayRecord {
            node_id: node_id.to_string(),
            address,
            x25519_public: keys.x25519.public().0,
            ml_kem_public_hash: keys.ml_kem_public_hash(),
            expires_at_unix,
        },
        node_id,
        &keys.identity_signing,
    )
}

fn directory_upsert_command(signed: &chronos_dir::signed_record::SignedRelayRecord) -> String {
    format!(
        "UPSERT_SIGNED {} {} {} {} {} {} {} {}",
        signed.record.node_id,
        signed.record.address,
        signed.record.expires_at_unix,
        hex(&signed.record.x25519_public),
        hex(&signed.record.ml_kem_public_hash),
        signed.signer_id,
        hex(&signed.verifying_key),
        hex(&signed.signature),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn display_relay_error(context: &'static str) -> impl FnOnce(UdpRelayError) -> String {
    move |error| format!("{context}: {error:?}")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn run_legacy_mode() -> Result<(), Box<dyn Error>> {
    let mode = std::env::var("CHRONOS_NETTEST_MODE").unwrap_or_else(|_| "smoke".to_string());
    let packets = std::env::var("CHRONOS_NETTEST_PACKETS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(match mode.as_str() {
            "leak-audit" => 2_000,
            "mix-sweep" => 128,
            _ => 64,
        });
    match mode.as_str() {
        "smoke" => run_smoke(packets)?,
        "mix-sweep" => run_mix_sweep(packets)?,
        "fec-compare" => run_fec_compare()?,
        "leak-audit" => run_leak_audit(packets)?,
        other => {
            return Err(format!(
                "unknown CHRONOS_NETTEST_MODE={other}; expected smoke|mix-sweep|fec-compare|leak-audit"
            )
            .into());
        }
    }
    Ok(())
}

fn run_smoke(packets: usize) -> Result<(), Box<dyn Error>> {
    let (pairs, report, egress) = simulate_adaptive_mix(MixProfile::Normal, packets, 2, 1228, 1228);
    if pairs.len() != packets || egress.is_empty() {
        return Err("smoke experiment did not produce the expected local trace".into());
    }
    let payload: Vec<u8> = (0..120u8).collect();
    let fec = encode_payload_with_repair(&payload, 8, 4)?;
    println!(
        "smoke: profile={} mi_bits={:.4} p50_us={} repair={}",
        report.profile, report.mi_bits, report.latency.p50_us, fec.repair
    );
    Ok(())
}

fn run_mix_sweep(packets: usize) -> Result<(), Box<dyn Error>> {
    print!(
        "{}",
        sweep_mix_k_latency_csv(packets, &[1, 2, 5, 10, 20, 50])
    );
    Ok(())
}

fn run_fec_compare() -> Result<(), Box<dyn Error>> {
    println!("codec,payload_len,symbols_sent,symbols_needed,overhead_ratio");
    for &len in &[64usize, 200, 500, 1000] {
        let payload: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
        for row in compare_fec_overhead(&payload, 10, 12) {
            println!(
                "{},{},{},{},{:.4}",
                row.codec,
                row.payload_len,
                row.symbols_sent,
                row.symbols_needed,
                row.overhead_ratio
            );
        }
    }
    Ok(())
}

fn run_leak_audit(packets: usize) -> Result<(), Box<dyn Error>> {
    if packets < 100 {
        return Err("leak-audit requires CHRONOS_NETTEST_PACKETS >= 100".into());
    }
    for profile in [
        MixProfile::Fast,
        MixProfile::Normal,
        MixProfile::HighAnonymity,
    ] {
        let (pairs, report, _) = simulate_adaptive_mix(profile, packets, 5, 1228, 1228);
        let measured_mi = mutual_information_timing(&pairs, 16);
        println!(
            "leak-audit: profile={} packets={} mi_bits={:.6} measured_mi={:.6}",
            report.profile, report.packets, report.mi_bits, measured_mi
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_supported_scenarios_and_rejects_invalid_input() {
        let cli = parse_cli([
            "--scenario".to_string(),
            "three-hop-local".to_string(),
            "--out".to_string(),
            "report.json".to_string(),
        ])
        .expect("parse");
        assert_eq!(cli.scenario, Some(Scenario::ThreeHopLocal));
        assert_eq!(cli.out, Some(PathBuf::from("report.json")));
        assert!(parse_cli(["--scenario".to_string(), "unknown".to_string()]).is_err());
        assert!(parse_cli(["--messages".to_string(), "0".to_string()]).is_err());
    }

    #[test]
    fn reports_serialize_to_json() {
        let report = DirectoryNegativeReport {
            scenario: "directory-negative",
            ok: true,
            cases: Vec::new(),
            errors: Vec::new(),
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("directory-negative"));
    }

    #[tokio::test]
    async fn directory_negative_scenario_reports_real_rejections() {
        assert!(run_directory_negative(1).await.ok);
    }

    #[tokio::test]
    async fn replay_scenario_rejects_a_replayed_route_packet() {
        let report = run_replay_negative(1).await;
        assert!(report.ok);
        assert_eq!(report.messages_delivered, 1);
        assert!(report.replay_rejected);
    }

    #[tokio::test]
    async fn three_hop_scenario_delivers_through_real_udp_relays() {
        let report = run_three_hop_local(1).await;
        assert!(report.ok);
        assert_eq!(report.directory_records_inserted, 3);
        assert_eq!(report.messages_delivered, 1);
        assert_eq!(report.relays, 3);
        assert_eq!(report.relay_bindings.len(), 3);
    }
}
