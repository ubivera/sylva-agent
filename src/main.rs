//! Sylva machine agent (Hub slice 2, CP1 spine) — a headless, always-on device
//! service. It generates a machine identity key, discovers + TOFU-pins a Sylva
//! Server, registers the machine (proving it holds the key), then runs a liveness
//! check-in loop and consumes the server's keep-alive/config push stream.
//!
//! This checkpoint is a **console binary** for dev. The Windows Service host (run
//! as SYSTEM, auto-start, hardened key store) lands in CP2; device telemetry
//! (encrypted to the device-admin group key) lands in CP3. See
//! `docs/design/agent.md`.

mod state;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use ed25519_dalek::{Signer, SigningKey};
use rand::{RngCore, rngs::OsRng};
use sylva_sdk::proto::machine::v1::{
    CheckInRequest, Empty, RegisterMachineRequest, machine_client::MachineClient, server_push,
};
use sylva_sdk::transport::{self, ConnectError, TrustDecision};
use tonic::transport::Channel;

use state::AgentState;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const CHECK_IN_INTERVAL: Duration = Duration::from_secs(60);

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
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cfg = Config::from_env()?;
    tracing::info!(host = %cfg.host, port = cfg.discovery_port, "sylva-agent starting");

    let mut st = AgentState::load(&cfg.state_path)
        .with_context(|| format!("loading agent state from {}", cfg.state_path.display()))?;

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

    // 4. Run the check-in loop + the push-stream consumer until Ctrl-C / error.
    tokio::select! {
        result = check_in_loop(client.clone(), token.clone()) => result?,
        result = subscribe_loop(client.clone(), token) => result?,
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

/// Hold the server push stream open and log what arrives (config + keep-alives).
async fn subscribe_loop(mut client: MachineClient<Channel>, token: String) -> anyhow::Result<()> {
    let mut stream = client
        .subscribe(authed(&token, Empty {}))
        .await
        .context("subscribe failed")?
        .into_inner();
    while let Some(push) = stream.message().await.context("server push stream error")? {
        match push.payload {
            Some(server_push::Payload::Config(cfg)) => {
                tracing::info!(location_enabled = cfg.location_enabled, "config push");
            }
            Some(server_push::Payload::KeepAlive(_)) => tracing::debug!("keep-alive"),
            None => {}
        }
    }
    tracing::info!("server closed the push stream");
    Ok(())
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
            "server identity does not match the pinned key — refusing to connect \
             (delete the agent state to re-pin a known-good server)"
        ),
        other => anyhow!("could not reach or verify the server: {other:?}"),
    }
}
