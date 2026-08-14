// SPDX-License-Identifier: MIT

//! The self-extracting loader.
//!
//! When a packed binary runs, `main` detects the trailing footer and hands off
//! to [`run`] instead of the CLI. The loader reads its own file, recovers the
//! original executable into a per-user cache, and executes it — transparently
//! forwarding the process arguments — so a packed program behaves exactly like
//! the original.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::format;
use crate::util::write_executable;

/// Run as the loader for a packed binary. On success this replaces the current
/// process (on Unix) or exits with the child's status (elsewhere) and does not
/// return; it only returns `Err` when extraction or launch fails.
pub fn run(exe: &Path) -> Result<()> {
    let bytes =
        fs::read(exe).with_context(|| format!("reading packed binary {}", exe.display()))?;

    let (footer, name) = format::peek(&bytes)?;
    let target = cache_path(&name, footer.crc32)?;

    // Fast path: a previous run already materialized this exact original
    // (verified by crc32, which also guards against a poisoned cache file).
    if !cache_is_valid(&target, footer.crc32) {
        let extracted = format::extract(&bytes)?;
        write_executable(&target, &extracted.original)
            .with_context(|| format!("writing extracted binary to {}", target.display()))?;
    }

    exec(&target)
}

/// Location of the cached, extracted original. Keyed by name and crc32 so
/// different versions never collide and a stale cache is never reused.
fn cache_path(name: &str, crc32: u32) -> Result<PathBuf> {
    let mut dir = std::env::temp_dir();
    dir.push("cargo-pack");
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating cache directory {}", dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best effort: keep the cache directory private to this user.
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }

    // Sanitize the name so it can't escape the cache directory.
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    dir.push(format!("{crc32:08x}-{safe}"));
    Ok(dir)
}

/// Whether `path` exists and its contents match the expected crc32.
fn cache_is_valid(path: &Path, expected_crc: u32) -> bool {
    match fs::read(path) {
        Ok(contents) => crc32fast::hash(&contents) == expected_crc,
        Err(_) => false,
    }
}

#[cfg(unix)]
fn exec(target: &Path) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // `exec` replaces this process image; it only returns on failure.
    let err = std::process::Command::new(target)
        .args(std::env::args_os().skip(1))
        .exec();
    Err(err).with_context(|| format!("executing {}", target.display()))
}

#[cfg(not(unix))]
fn exec(target: &Path) -> Result<()> {
    use std::process::Command;
    let status = Command::new(target)
        .args(std::env::args_os().skip(1))
        .status()
        .with_context(|| format!("executing {}", target.display()))?;
    std::process::exit(status.code().unwrap_or(1));
}
