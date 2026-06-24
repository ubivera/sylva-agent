//! Machine-scoped persistent state: the agent's Ed25519 identity-key seed, the
//! TOFU-pinned server identity, and the registered machine id + session token.
//!
//! ponytail: dev persists this as a plain JSON file. The hardened machine-scoped
//! store (Windows DPAPI LocalMachine / a SYSTEM-only ACL'd path) lands with the
//! Windows Service host in CP2, where the agent runs as SYSTEM. The on-disk shape
//! is stable, so swapping the backend won't disturb callers.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AgentState {
    /// 32-byte Ed25519 machine identity signing-key seed.
    pub machine_key_seed: Option<Vec<u8>>,
    /// The TOFU-pinned server identity public key (Ed25519, 32 bytes).
    pub server_identity: Option<Vec<u8>>,
    /// The server-assigned machine id (UUID), once registered.
    pub machine_id: Option<String>,
    /// The current machine session token (the bearer for CheckIn/Subscribe).
    pub session_token: Option<String>,
}

impl AgentState {
    /// Load from `path`, or a fresh default if the file doesn't exist yet.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err.into()),
        }
    }

    /// Persist to `path` (creating parent dirs).
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}
