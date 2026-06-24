//! Sylva machine agent (Hub slice 2, CP1 spine) — a headless, always-on device
//! service. It generates a machine identity key, discovers + TOFU-pins a Sylva
//! Server, registers the machine (proving it holds the key), then runs a liveness
//! check-in loop and consumes the server's keep-alive/config push stream.
//!
//! This checkpoint is a **console binary** for dev. The Windows Service host (run
//! as SYSTEM, auto-start, hardened key store) lands in CP2; device telemetry
//! (encrypted to the device-admin group key) lands in CP3. See
//! `docs/design/agent.md`.

mod collector;
mod probe;
mod state;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use ed25519_dalek::{Signer, SigningKey};
use rand::{RngCore, rngs::OsRng};
use sylva_sdk::proto::machine::v1::{
    CheckInRequest, Empty, MachineConfig, RegisterMachineRequest, ReportTelemetryRequest,
    TelemetryBlob, machine_client::MachineClient, server_push,
};
use sylva_sdk::transport::{self, ConnectError, TrustDecision};
use tonic::transport::Channel;

use collector::LocationCollector;
use state::AgentState;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const CHECK_IN_INTERVAL: Duration = Duration::from_secs(60);
/// How often to collect + report location when it's enabled. ponytail: fixed
/// interval for now; server-driven cadence is a later refinement.
const REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Where to find the server + where to keep machine-scoped state.
struct Config {
    host: String,
    discovery_port: u16,
    state_path: PathBuf,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let host = std::env::var("SYLVA_SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let discovery_port = match std::env::var("SYLVA_SERVER_DISCOVERY_PORT") {
            Ok(s) => s
                .parse()
                .with_context(|| format!("SYLVA_SERVER_DISCOVERY_PORT is not a port: {s}"))?,
            Err(_) => 8443,
        };
        let state_path = std::env::var("SYLVA_AGENT_STATE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("sylva-agent-state.json"));
        Ok(Self {
            host,
            discovery_port,
            state_path,
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // One-shot diagnostic: probe the OS location API, print the result, exit.
    // Run as your user AND as SYSTEM (PsExec -s) to learn the service-context
    // behavior before the collector is built. Bypasses the normal agent flow.
    if std::env::args().skip(1).any(|a| a == "--probe-location") {
        return probe::run();
    }

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cfg = Config::from_env()?;
    tracing::info!(host = %cfg.host, port = cfg.discovery_port, "sylva-agent starting");

    let mut st = AgentState::load(&cfg.state_path)
        .with_context(|| format!("loading agent state from {}", cfg.state_path.display()))?;

    // `--reset`: forget the pinned server + stale session (keeping the machine
    // identity key) so the agent re-pins on the next connect. The deliberate
    // escape hatch for a legitimately rotated server identity (e.g. a dev DB
    // recreate). NOT automatic — an unexpected identity change must refuse, not
    // silently re-trust.
    if std::env::args().skip(1).any(|a| a == "--reset") {
        tracing::warn!("--reset: forgetting the pinned server + session; will re-pin on connect");
        st.server_identity = None;
        st.machine_id = None;
        st.session_token = None;
        st.save(&cfg.state_path)?;
    }

    // 1. Machine identity key — generated once, then persisted + reused.
    let signing_key = load_or_create_key(&mut st, &cfg.state_path)?;
    let public = signing_key.verifying_key().to_bytes();

    // 2. Discover + verify + TOFU-pin the server; the returned channel is its gRPC port.
    let pinned: Option<[u8; 32]> = match &st.server_identity {
        Some(bytes) => Some(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("stored server identity is not 32 bytes"))?,
        ),
        None => None,
    };
    let (channel, verified, decision) =
        transport::discover_and_connect(&cfg.host, cfg.discovery_port, pinned.as_ref())
            .await
            .map_err(describe_connect)?;
    if matches!(decision, TrustDecision::FirstContact) {
        tracing::info!(server = %verified.name, "first contact — pinning server identity");
        st.server_identity = Some(verified.identity_public.to_vec());
        st.save(&cfg.state_path)?;
    } else {
        tracing::info!(server = %verified.name, "server identity matches the pinned key");
    }

    // 3. Register the machine (idempotent on the identity key) → a session token.
    //    ponytail: register every startup for a fresh token; on token expiry the
    //    check-in loop errors out and the process exits — the service host (CP2)
    //    restarts it. Inline re-register lands if/when that churn matters.
    let mut client = MachineClient::new(channel);
    let token = register(&mut client, &mut st, &cfg, &signing_key, &public).await?;
    tracing::info!(machine_id = ?st.machine_id, "registered; entering run loop");

    // 4. Run: check-in loop + push-stream consumer + location-report loop until
    //    Ctrl-C / error. The subscribe consumer publishes the latest server config
    //    to a watch channel; the report loop reads it to decide whether to collect.
    let (config_tx, config_rx) = tokio::sync::watch::channel(MachineConfig::default());
    let collector: Box<dyn LocationCollector> = Box::new(collector::WindowsLocationCollector);

    tokio::select! {
        result = check_in_loop(client.clone(), token.clone()) => result?,
        result = subscribe_loop(client.clone(), token.clone(), config_tx) => result?,
        result = report_loop(client.clone(), token, config_rx, collector) => result?,
        _ = tokio::signal::ctrl_c() => tracing::info!("received Ctrl-C, shutting down"),
    }
    Ok(())
}

/// Load the persisted machine signing key, or generate + persist a new one.
fn load_or_create_key(st: &mut AgentState, path: &std::path::Path) -> anyhow::Result<SigningKey> {
    if let Some(seed) = &st.machine_key_seed {
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("stored machine key seed is not 32 bytes"))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    st.machine_key_seed = Some(seed.to_vec());
    st.save(path)?;
    tracing::info!("generated a new machine identity key");
    Ok(key)
}

/// Register the machine with the server, proving possession of the identity key,
/// and persist the assigned id + session token. Returns the token.
async fn register(
    client: &mut MachineClient<Channel>,
    st: &mut AgentState,
    cfg: &Config,
    signing_key: &SigningKey,
    public: &[u8; 32],
) -> anyhow::Result<String> {
    let platform = std::env::consts::OS.to_string();
    let label = machine_label();
    let signature = signing_key
        .sign(&canonical_machine_bytes(public, &platform, &label))
        .to_bytes()
        .to_vec();
    let session = client
        .register_machine(tonic::Request::new(RegisterMachineRequest {
            machine_identity_public: public.to_vec(),
            platform,
            label,
            signature,
        }))
        .await
        .context("register_machine failed")?
        .into_inner();
    st.machine_id = Some(session.machine_id.clone());
    st.session_token = Some(session.token.clone());
    st.save(&cfg.state_path)?;
    Ok(session.token)
}

/// Periodic liveness heartbeat. Errors (incl. a 401 on token expiry) bubble up
/// and end the run.
async fn check_in_loop(mut client: MachineClient<Channel>, token: String) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(CHECK_IN_INTERVAL);
    loop {
        ticker.tick().await; // fires immediately, then every interval
        client
            .check_in(authed(
                &token,
                CheckInRequest {
                    agent_version: AGENT_VERSION.to_string(),
                },
            ))
            .await
            .context("check-in failed")?;
        tracing::info!("checked in");
    }
}

/// Hold the server push stream open; publish each config to the watch channel
/// (the report loop reads it) and log keep-alives.
async fn subscribe_loop(
    mut client: MachineClient<Channel>,
    token: String,
    config_tx: tokio::sync::watch::Sender<MachineConfig>,
) -> anyhow::Result<()> {
    let mut stream = client
        .subscribe(authed(&token, Empty {}))
        .await
        .context("subscribe failed")?
        .into_inner();
    while let Some(push) = stream.message().await.context("server push stream error")? {
        match push.payload {
            Some(server_push::Payload::Config(cfg)) => {
                tracing::info!(
                    location_enabled = cfg.location_enabled,
                    has_group = !cfg.device_admin_group_public.is_empty(),
                    "config push"
                );
                let _ = config_tx.send(cfg);
            }
            Some(server_push::Payload::KeepAlive(_)) => tracing::debug!("keep-alive"),
            None => {}
        }
    }
    tracing::info!("server closed the push stream");
    Ok(())
}

/// When location is enabled AND a device-admin group key is provisioned, collect
/// a fix, seal it to the group key, and report it on a schedule. Collection
/// failures (e.g. the OS location service is off) are logged + skipped, not fatal.
async fn report_loop(
    mut client: MachineClient<Channel>,
    token: String,
    config_rx: tokio::sync::watch::Receiver<MachineConfig>,
    collector: Box<dyn LocationCollector>,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(REPORT_INTERVAL);
    ticker.tick().await; // consume the immediate first tick
    let mut seq: u64 = 0;
    loop {
        ticker.tick().await;
        let config = config_rx.borrow().clone();
        if !config.location_enabled || config.device_admin_group_public.is_empty() {
            continue;
        }
        let Ok(group_public): std::result::Result<[u8; 32], _> =
            config.device_admin_group_public.as_slice().try_into()
        else {
            tracing::warn!("device-admin group public key is not 32 bytes; skipping report");
            continue;
        };
        let fix = match collector.collect() {
            Ok(fix) => fix,
            Err(err) => {
                tracing::warn!(?err, "location collection failed; skipping this report");
                continue;
            }
        };
        let ciphertext = match collector::encode_fix(&fix)
            .and_then(|pt| Ok(sylva_sdk::crypto::seal_to(&group_public, &pt)?))
        {
            Ok(ct) => ct,
            Err(err) => {
                tracing::warn!(?err, "encrypting the fix failed; skipping this report");
                continue;
            }
        };
        seq += 1;
        let blob = TelemetryBlob {
            kind: "location".to_string(),
            recipient_key_id: config.group_key_id.clone(),
            seq,
            ciphertext,
            signature: Vec::new(),
        };
        client
            .report_telemetry(authed(
                &token,
                ReportTelemetryRequest { blobs: vec![blob] },
            ))
            .await
            .context("report_telemetry failed")?;
        tracing::info!(accuracy_m = fix.accuracy_m, "reported location");
    }
}

/// Wrap a message in a request carrying the machine session token.
fn authed<T>(token: &str, message: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    if let Ok(value) = format!("Bearer {token}").parse() {
        request.metadata_mut().insert("authorization", value);
    }
    request
}

/// The bytes the agent signs at registration (must match the server's
/// `canonical_machine_bytes`).
fn canonical_machine_bytes(public: &[u8], platform: &str, label: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sylva-machine-registration:v1\n");
    v.extend_from_slice(public);
    v.push(b'\n');
    v.extend_from_slice(platform.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(label.as_bytes());
    v
}

/// A human-ish machine label (hostname), with a stable fallback.
fn machine_label() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "sylva-agent".to_string())
}

fn describe_connect(err: ConnectError) -> anyhow::Error {
    match err {
        ConnectError::IdentityMismatch => anyhow!(
            "server identity does not match the pinned key — refusing to connect. \
             If the server legitimately rotated its identity (e.g. a dev DB recreate), \
             re-run with `--reset` to forget the old pin and re-pin."
        ),
        other => anyhow!("could not reach or verify the server: {other:?}"),
    }
}
