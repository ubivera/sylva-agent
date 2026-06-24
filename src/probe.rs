//! One-shot location probe (`--probe-location`): calls the Windows Geolocation
//! API once and prints the fix or the error, then exits. Run it as your user AND
//! as SYSTEM (`PsExec -s`) to learn whether a service-context process can get a
//! fix — the CP3 de-risking spike before the agent commits to a collector.
//!
//! ponytail: probe only — raw OS call, no pipeline. The real `LocationCollector`
//! (trait + fake for tests) lands with the CP3 telemetry pipeline. All calls here
//! are the windows-rs *safe* wrappers, so the crate's `forbid(unsafe)` holds.

#[cfg(windows)]
pub fn run() -> anyhow::Result<()> {
    use anyhow::Context;
    use windows::Devices::Geolocation::Geolocator;

    println!("[probe] Windows Geolocation — Geolocator.GetGeopositionAsync");

    let locator = Geolocator::new().context("create Geolocator")?;
    match locator.LocationStatus() {
        Ok(status) => println!("[probe] LocationStatus = {status:?}"),
        Err(err) => println!("[probe] LocationStatus error: {err}"),
    }

    let position = locator
        .GetGeopositionAsync()
        .context("GetGeopositionAsync (call)")?
        .get()
        .context("awaiting a fix — location off, no consent, or no sensor in this context?")?;

    let coord = position.Coordinate().context("Coordinate")?;
    let point = coord.Point().context("Point")?;
    let basic = point.Position().context("Position")?;
    let accuracy = coord.Accuracy().unwrap_or(f64::NAN);

    println!(
        "[probe] FIX  lat={:.6}  lon={:.6}  accuracy={:.1} m",
        basic.Latitude, basic.Longitude, accuracy
    );
    println!("[probe] OK — this context can obtain a location fix.");
    Ok(())
}

#[cfg(not(windows))]
pub fn run() -> anyhow::Result<()> {
    println!("[probe] location probe is Windows-only for now");
    Ok(())
}
