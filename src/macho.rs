// SPDX-License-Identifier: MIT

//! Minimal, safe Mach-O manipulation used by the packer on macOS.
//!
//! `codesign` requires the code signature to be the very last thing in the file,
//! so cargo-pack cannot append its payload as a trailing overlay on macOS (that
//! would leave data after the signature and fail strict validation). Instead the
//! payload is embedded *inside* the last segment (`__LINKEDIT`), before the
//! signature: [`embed_payload`] grows `__LINKEDIT` to cover appended bytes, and
//! the loader finds them by treating [`code_signature_offset`] as the logical
//! end of the file rather than EOF.
//!
//! Everything here is plain byte manipulation of a thin 64-bit little-endian
//! Mach-O (what rustc/cargo produce for the host) plus `codesign` subprocesses —
//! no `unsafe`, no load-command insertion, no chained-fixups surgery.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};

use crate::util::unique_tmpdir;

const MH_MAGIC_64: u32 = 0xFEED_FACF;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1D;

/// arm64 macOS page size; used to keep `__LINKEDIT`'s `vmsize` page-aligned.
const PAGE: u64 = 0x4000;

fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn rd_u64(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// Whether `bytes` is a thin 64-bit little-endian Mach-O.
pub fn is_macho(bytes: &[u8]) -> bool {
    rd_u32(bytes, 0) == Some(MH_MAGIC_64)
}

/// File offset of the `LC_CODE_SIGNATURE` data, i.e. the logical end of the
/// signed content. `None` for an unsigned or non-Mach-O binary.
pub fn code_signature_offset(bytes: &[u8]) -> Option<usize> {
    for_each_command(bytes, |cmd, off| {
        if cmd == LC_CODE_SIGNATURE {
            rd_u32(bytes, off + 8).map(|d| d as usize)
        } else {
            None
        }
    })
}

/// File offsets of a Mach-O section's `sectname` field and its data.
/// Used only by the macOS SBOM slot path.
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
pub struct Section {
    pub name_off: usize,
    pub data_off: usize,
    pub size: usize,
}

/// Find a section by name, returning the offsets of its `section_64` name field
/// and its data.
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
pub fn find_section(bytes: &[u8], section: &str) -> Option<Section> {
    for_each_command(bytes, |cmd, cmd_off| {
        if cmd != LC_SEGMENT_64 {
            return None;
        }
        let nsects = rd_u32(bytes, cmd_off + 64)? as usize;
        for i in 0..nsects {
            let s = cmd_off + 72 + i * 80; // section_64 is 80 bytes
            let name_bytes = bytes.get(s..s + 16)?;
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
            if std::str::from_utf8(&name_bytes[..end]) == Ok(section) {
                return Some(Section {
                    name_off: s,
                    size: usize::try_from(rd_u64(bytes, s + 40)?).ok()?, // section_64.size
                    data_off: rd_u32(bytes, s + 48)? as usize,           // section_64.offset
                });
            }
        }
        None
    })
}

/// Rename a section's 16-byte `sectname` in place (new name must fit in 16
/// bytes, null-padded). Used only by the macOS SBOM slot path.
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
pub fn rename_section(bytes: &mut [u8], section: &Section, new_name: &str) {
    let mut name = [0u8; 16];
    let n = new_name.len().min(16);
    name[..n].copy_from_slice(&new_name.as_bytes()[..n]);
    bytes[section.name_off..section.name_off + 16].copy_from_slice(&name);
}

/// Append `payload` inside the `__LINKEDIT` segment (which must be last), so the
/// bytes fall within the signed region once `codesign` runs. Pads *before* the
/// payload so the payload — and thus its trailing container trailer — ends on a
/// 16-byte boundary, which is where `codesign` places the signature; the loader
/// can then read the trailer at exactly `code_signature_offset`.
pub fn embed_payload(buf: &mut Vec<u8>, payload: &[u8]) -> Result<()> {
    let cmd_off = linkedit_command(buf).context("Mach-O has no __LINKEDIT segment")?;
    let vmsize = rd_u64(buf, cmd_off + 32).context("truncated __LINKEDIT")?;
    let fileoff = rd_u64(buf, cmd_off + 40).context("truncated __LINKEDIT")?;
    let filesize = rd_u64(buf, cmd_off + 48).context("truncated __LINKEDIT")?;

    let linkedit_end = usize::try_from(fileoff + filesize).context("__LINKEDIT too large")?;
    ensure!(
        linkedit_end == buf.len(),
        "expected __LINKEDIT to be last with no trailing data (end {linkedit_end}, file {})",
        buf.len()
    );

    // Pad first so the payload ends 16-aligned.
    let pad = (16 - (buf.len() + payload.len()) % 16) % 16;
    buf.resize(buf.len() + pad, 0);
    buf.extend_from_slice(payload);

    let added = (pad + payload.len()) as u64;
    let new_filesize = filesize + added;
    let new_vmsize = (vmsize + added).div_ceil(PAGE) * PAGE;
    buf[cmd_off + 32..cmd_off + 40].copy_from_slice(&new_vmsize.to_le_bytes());
    buf[cmd_off + 48..cmd_off + 56].copy_from_slice(&new_filesize.to_le_bytes());
    Ok(())
}

/// Remove any existing code signature via `codesign`, returning the clean bytes.
/// A no-op (returns the input) if the binary isn't signed.
pub fn remove_signature(bytes: &[u8]) -> Result<Vec<u8>> {
    if code_signature_offset(bytes).is_none() {
        return Ok(bytes.to_vec());
    }
    run_codesign(bytes, &["--remove-signature"])
}

/// Ad-hoc sign the Mach-O, returning the signed bytes.
pub fn codesign_adhoc(bytes: &[u8]) -> Result<Vec<u8>> {
    run_codesign(bytes, &["--force", "--sign", "-"])
}

/// Write `bytes` to a temp file, run `codesign` with `args`, read it back.
fn run_codesign(bytes: &[u8], args: &[&str]) -> Result<Vec<u8>> {
    let dir = unique_tmpdir()?;
    let path = dir.join("macho");
    let result = (|| {
        std::fs::write(&path, bytes).context("writing Mach-O to a temp file")?;
        run_codesign_file(&path, args)?;
        std::fs::read(&path).context("reading the signed Mach-O")
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn run_codesign_file(path: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("codesign")
        .args(args)
        .arg(path)
        .status()
        .context("running codesign")?;
    ensure!(status.success(), "codesign {args:?} failed");
    Ok(())
}

/// Offset of the `LC_SEGMENT_64` load command for `__LINKEDIT`.
fn linkedit_command(bytes: &[u8]) -> Option<usize> {
    for_each_command(bytes, |cmd, off| {
        if cmd != LC_SEGMENT_64 {
            return None;
        }
        let name = bytes.get(off + 8..off + 24)?;
        let end = name.iter().position(|&b| b == 0).unwrap_or(16);
        (&name[..end] == b"__LINKEDIT").then_some(off)
    })
}

/// Walk the load commands, returning the first `Some` produced by `f(cmd, off)`.
fn for_each_command<T>(bytes: &[u8], mut f: impl FnMut(u32, usize) -> Option<T>) -> Option<T> {
    if !is_macho(bytes) {
        return None;
    }
    let ncmds = rd_u32(bytes, 16)? as usize;
    let mut off = 32; // sizeof(mach_header_64)
    for _ in 0..ncmds {
        let cmd = rd_u32(bytes, off)?;
        let cmdsize = rd_u32(bytes, off + 4)? as usize;
        if cmdsize == 0 {
            return None;
        }
        if let Some(v) = f(cmd, off) {
            return Some(v);
        }
        off = off.checked_add(cmdsize)?;
    }
    None
}
