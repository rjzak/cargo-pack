// SPDX-License-Identifier: MIT

//! Small filesystem and formatting helpers shared across commands.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::format;

/// Read a file and return its *original* (unpacked) contents.
///
/// If the file is already a packed binary this transparently extracts the
/// original payload, which makes `cargo pack build` idempotent: re-packing an
/// already-packed artifact reproduces the original before packing again instead
/// of nesting a pack inside a pack.
pub fn read_original(bytes: &[u8]) -> Result<Vec<u8>> {
    if format::is_packed(bytes) {
        Ok(format::extract(bytes)
            .context("re-reading an already-packed binary")?
            .original)
    } else {
        Ok(bytes.to_vec())
    }
}

/// Write `bytes` to `path` and mark it executable (on Unix), preserving the
/// destination's existing permission bits when it already exists.
pub fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    // Write to a sibling temp file then rename, so an interrupted write never
    // leaves a half-written executable in place.
    let tmp = tmp_sibling(path);
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).map_or(0o755, |m| m.permissions().mode()) | 0o755;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting permissions on {}", tmp.display()))?;
    }

    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// A temp path in the same directory as `path` (so `rename` stays on one
/// filesystem and is atomic).
fn tmp_sibling(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".cargo-pack.tmp");
    match path.parent() {
        Some(dir) => dir.join(name),
        None => std::path::PathBuf::from(name),
    }
}

/// Packed size as a percentage of the original, for display only.
///
/// The `f64` conversion can lose precision for multi-petabyte inputs, which is
/// irrelevant at the resolution we print.
#[allow(clippy::cast_precision_loss)]
pub fn ratio_percent(packed: u64, original: u64) -> f64 {
    if original == 0 {
        0.0
    } else {
        packed as f64 / original as f64 * 100.0
    }
}

/// Format a byte count as a short human-readable string (e.g. `3.4 MiB`).
#[allow(clippy::cast_precision_loss)]
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
