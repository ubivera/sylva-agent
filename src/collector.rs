//! Location collection (CP3). `LocationCollector` abstracts the OS location fix
//! so the report pipeline is testable with a fake — no GPS, no SYSTEM. The real
//! Windows collector reuses the `Geolocator` path proven by `--probe-location`,
//! and degrades gracefully (returns `Err`, never panics) when no fix is available.

use serde::{Deserialize, Serialize};

/// A point-in-time device location fix. This is the plaintext that gets sealed to
/// the device-admin group key — the server only ever sees the ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LocationFix {
    #[serde(rename = "lat")]
    pub latitude: f64,
    #[serde(rename = "lon")]
    pub longitude: f64,
    #[serde(rename = "accuracy_m")]
    pub accuracy_m: f64,
}

/// Obtains a device location fix. Implementations degrade gracefully — `Err` when
/// no fix is available (location service off, no sensor), never a panic.
pub trait LocationCollector: Send + Sync {
    fn collect(&self) -> anyhow::Result<LocationFix>;
}

/// Serialize a fix to the bytes sealed to the device-admin group key.
pub fn encode_fix(fix: &LocationFix) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(fix)?)
}

/// A fixed fix — for tests without a sensor. (Test-only for now; lift the
/// `#[cfg(test)]` if a `--fake-location` dev mode is ever wanted.)
#[cfg(test)]
pub struct FakeLocationCollector {
    pub fix: LocationFix,
}

#[cfg(test)]
impl LocationCollector for FakeLocationCollector {
    fn collect(&self) -> anyhow::Result<LocationFix> {
        Ok(self.fix)
    }
}

/// The real Windows collector (same `Geolocator` call as the probe).
#[cfg(windows)]
pub struct WindowsLocationCollector;

#[cfg(windows)]
impl LocationCollector for WindowsLocationCollector {
    fn collect(&self) -> anyhow::Result<LocationFix> {
        use anyhow::Context;
        use windows::Devices::Geolocation::Geolocator;

        let locator = Geolocator::new().context("create Geolocator")?;
        let position = locator
            .GetGeopositionAsync()
            .context("GetGeopositionAsync")?
            .get()
            .context("awaiting a location fix (lfsvc off / no sensor?)")?;
        let coord = position.Coordinate().context("Coordinate")?;
        let basic = coord
            .Point()
            .context("Point")?
            .Position()
            .context("Position")?;
        Ok(LocationFix {
            latitude: basic.Latitude,
            longitude: basic.Longitude,
            accuracy_m: coord.Accuracy().unwrap_or(f64::NAN),
        })
    }
}

/// Off-Windows stub so the crate stays cross-platform; collection is Windows-only
/// for now (macOS/Linux collectors land with those service hosts).
#[cfg(not(windows))]
pub struct WindowsLocationCollector;

#[cfg(not(windows))]
impl LocationCollector for WindowsLocationCollector {
    fn collect(&self) -> anyhow::Result<LocationFix> {
        anyhow::bail!("location collection is only implemented on Windows")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use sylva_sdk::crypto::{generate_group_keypair, open_sealed, seal_to};

    #[test]
    fn fake_fix_seals_to_the_group_and_an_admin_decrypts() {
        let fix = LocationFix {
            latitude: 35.594566,
            longitude: -77.408395,
            accuracy_m: 27.0,
        };
        let collector = FakeLocationCollector { fix };
        assert_eq!(collector.collect().unwrap(), fix);

        // The agent seals the fix to the device-admin group public key...
        let group = generate_group_keypair();
        let plaintext = encode_fix(&fix).unwrap();
        let ciphertext = seal_to(&group.public, &plaintext).unwrap();
        assert_ne!(ciphertext, plaintext, "stored blob is ciphertext, not plaintext");

        // ...the server stores ciphertext; an admin with the group secret decrypts.
        let opened = open_sealed(&group.secret, &ciphertext).unwrap();
        let recovered: LocationFix = serde_json::from_slice(&opened).unwrap();
        assert_eq!(recovered, fix);
    }
}
