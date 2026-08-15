// SPDX-License-Identifier: MIT

//! Preserving [`cargo-auditable`](https://github.com/rust-secure-code/cargo-auditable)
//! metadata across packing.
//!
//! `cargo auditable build` embeds a compressed dependency SBOM into a linker
//! section named `.dep-v0`, which `cargo audit bin` reads. But `cargo pack`
//! replaces the application binary with the cargo-pack loader stub and hides the
//! original (SBOM and all) inside the compressed overlay, so tools that inspect
//! the packed file no longer see the section. To keep the packed binary
//! auditable, we copy the original's `.dep-v0` into the stub *before* the
//! overlay is appended.
//!
//! Two mechanisms, picked by the stub's object format:
//!
//! * **ELF and PE** (Linux, the BSDs, Solaris, Haiku, Windows, …): add the
//!   section with `objcopy`/`llvm-objcopy`. No signature to worry about, and a
//!   section is only ever present when there is real data.
//! * **Mach-O** (macOS): `llvm-objcopy`'s Mach-O writer is broken and adding a
//!   segment to a modern arm64 binary would mean rewriting its chained-fixups
//!   metadata. Instead the stub carries a fixed-size, neutrally-named slot
//!   ([`SLOT_SECTION`]); at pack time we overwrite the slot's bytes with the
//!   SBOM and rename it to `.dep-v0` in place — no structural change — then
//!   re-sign ad-hoc. Renaming means a binary without an SBOM never exposes an
//!   empty `.dep-v0`, so `cargo audit bin` reports it accurately.
//!
//! Everything here is best-effort: with no SBOM, missing tooling, or an
//! oversized SBOM, packing proceeds unchanged. The original — SBOM and all — is
//! always recoverable with `cargo pack unpack`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result, ensure};
use object::{BinaryFormat, Object, ObjectSection};

/// The section cargo-auditable uses for its embedded SBOM.
const DEP_SECTION: &str = ".dep-v0";

/// What happened to the original's cargo-auditable SBOM during packing.
pub enum Sbom {
    /// The original carried no `.dep-v0` section; nothing to do.
    Absent,
    /// The SBOM was embedded into the returned stub bytes.
    Embedded(Vec<u8>),
    /// The original has an SBOM but it could not be embedded; the reason is
    /// suitable for a user-facing note.
    Skipped(String),
}

/// If `original` carries a cargo-auditable `.dep-v0` section, return a copy of
/// `stub` with that same section added, so the packed binary stays auditable.
pub fn preserve_sbom(stub: &[u8], original: &[u8]) -> Result<Sbom> {
    let Some(dep) = read_dep_section(original) else {
        return Ok(Sbom::Absent);
    };

    // The section is added to the *stub*, so the stub's object format decides
    // how (and whether) we can do it.
    match object::File::parse(stub).map(|f| f.format()).ok() {
        Some(BinaryFormat::Elf | BinaryFormat::Pe | BinaryFormat::Coff) => {
            objcopy_embed(stub, &dep)
        }
        Some(BinaryFormat::MachO) => macho_embed(stub, &dep),
        _ => Ok(Sbom::Skipped("unsupported executable format".into())),
    }
}

/// Read the `.dep-v0` section from an object file, if present.
fn read_dep_section(binary: &[u8]) -> Option<Vec<u8>> {
    let file = object::File::parse(binary).ok()?;
    let section = file.section_by_name(DEP_SECTION)?;
    Some(section.data().ok()?.to_vec())
}

// ---------------------------------------------------------------------------
// ELF / PE: add the section with objcopy.
// ---------------------------------------------------------------------------

fn objcopy_embed(stub: &[u8], dep: &[u8]) -> Result<Sbom> {
    let objcopy = find_objcopy().context(
        "cargo-auditable SBOM found but no objcopy was available; \
         install it with `rustup component add llvm-tools` (or your system's binutils)",
    )?;
    let dir = unique_tmpdir().context("creating a temporary directory")?;
    let result = objcopy_add_section(&objcopy, stub, dep, &dir);
    let _ = fs::remove_dir_all(&dir);
    result.map(Sbom::Embedded)
}

/// Run objcopy to add the `.dep-v0` section to `stub`, returning the new bytes.
fn objcopy_add_section(objcopy: &Path, stub: &[u8], data: &[u8], dir: &Path) -> Result<Vec<u8>> {
    let in_path = dir.join("stub.in");
    let dep_path = dir.join("dep-v0.bin");
    let out_path = dir.join("stub.out");

    fs::write(&in_path, stub).context("writing the stub to a temp file")?;
    fs::write(&dep_path, data).context("writing the SBOM to a temp file")?;

    let mut section_arg = OsString::from(format!("{DEP_SECTION}="));
    section_arg.push(&dep_path);

    let status = Command::new(objcopy)
        .arg("--add-section")
        .arg(section_arg)
        .arg(&in_path)
        .arg(&out_path)
        .status()
        .with_context(|| format!("running {}", objcopy.display()))?;
    ensure!(
        status.success(),
        "objcopy failed to add the {DEP_SECTION} section"
    );

    fs::read(&out_path).context("reading the SBOM-preserved stub")
}

/// Locate an objcopy: the toolchain's `llvm-tools` component first, then any
/// `llvm-objcopy`/`objcopy` on `PATH` (covers system binutils on the BSDs,
/// Solaris, Haiku, …).
fn find_objcopy() -> Option<PathBuf> {
    if let Some(path) = sysroot_objcopy() {
        return Some(path);
    }
    for name in ["llvm-objcopy", "rust-objcopy", "objcopy", "gobjcopy"] {
        if Command::new(name)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return Some(PathBuf::from(name));
        }
    }
    None
}

/// `<sysroot>/lib/rustlib/<host-triple>/bin/llvm-objcopy`, if the `llvm-tools`
/// component is installed.
fn sysroot_objcopy() -> Option<PathBuf> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let out = Command::new(rustc)
        .arg("--print")
        .arg("sysroot")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sysroot = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());

    let rustlib = sysroot.join("lib").join("rustlib");
    for entry in fs::read_dir(&rustlib).ok()?.flatten() {
        let candidate = entry.path().join("bin").join("llvm-objcopy");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Mach-O: overwrite and rename a pre-reserved slot, then re-sign.
// ---------------------------------------------------------------------------

/// Neutral name of the slot reserved in a macOS stub by `build.rs`
/// (`ld64 -sectcreate __DATA __cgpkslot`), renamed to `.dep-v0` when populated.
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
const SLOT_SECTION: &str = "__cgpkslot";

/// Bytes reserved for an embedded SBOM. Must match `build.rs`'s `SLOT_LEN`.
/// Large enough for very large dependency trees (the SBOM is compressed).
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
const SLOT_LEN: usize = 64 * 1024;

#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
fn macho_embed(stub: &[u8], dep: &[u8]) -> Result<Sbom> {
    let Some(slot) = find_macho_section(stub, SLOT_SECTION) else {
        return Ok(Sbom::Skipped(
            "this build of cargo-pack has no SBOM slot".into(),
        ));
    };
    if dep.len() > slot.size {
        return Ok(Sbom::Skipped(format!(
            "SBOM is {} bytes, larger than the {} KiB embed slot",
            dep.len(),
            SLOT_LEN / 1024
        )));
    }

    let mut out = stub.to_vec();
    // Overwrite the slot's data with the SBOM, zero-padding the remainder.
    out[slot.data_off..slot.data_off + dep.len()].copy_from_slice(dep);
    out[slot.data_off + dep.len()..slot.data_off + slot.size].fill(0);
    // Rename the section in place so it becomes `.dep-v0`.
    let mut name = [0u8; 16];
    name[..DEP_SECTION.len()].copy_from_slice(DEP_SECTION.as_bytes());
    out[slot.name_off..slot.name_off + 16].copy_from_slice(&name);

    // Editing the Mach-O invalidates its signature; re-sign the clean object
    // (before any overlay is appended, so codesign accepts it).
    let dir = unique_tmpdir().context("creating a temporary directory")?;
    let path = dir.join("stub.macho");
    let result = (|| {
        fs::write(&path, &out).context("writing the SBOM-preserved stub")?;
        codesign_adhoc(&path)?;
        fs::read(&path).context("reading the re-signed stub")
    })();
    let _ = fs::remove_dir_all(&dir);
    result.map(Sbom::Embedded)
}

// Signature must match the enabled variant, so the `Result` wrapper stays even
// though this arm never fails.
#[cfg(not(all(target_os = "macos", feature = "macos-auditable")))]
#[allow(clippy::unnecessary_wraps)]
fn macho_embed(_stub: &[u8], _dep: &[u8]) -> Result<Sbom> {
    Ok(Sbom::Skipped(
        "embedding into a Mach-O binary requires macOS with the `macos-auditable` feature".into(),
    ))
}

/// File offsets of a Mach-O section's name field and its data.
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
struct MachoSection {
    name_off: usize,
    data_off: usize,
    size: usize,
}

/// Find a section by name in a thin 64-bit little-endian Mach-O, returning the
/// file offsets of its `section_64` name field and its data.
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
fn find_macho_section(bytes: &[u8], section: &str) -> Option<MachoSection> {
    const MH_MAGIC_64: u32 = 0xFEED_FACF;
    const LC_SEGMENT_64: u32 = 0x19;

    let rd_u32 = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(o..o + 4)?.try_into().ok()?))
    };
    let rd_u64 = |o: usize| -> Option<u64> {
        Some(u64::from_le_bytes(bytes.get(o..o + 8)?.try_into().ok()?))
    };

    if rd_u32(0)? != MH_MAGIC_64 {
        return None;
    }
    let ncmds = rd_u32(16)? as usize;

    let mut cmd_off = 32; // sizeof(mach_header_64)
    for _ in 0..ncmds {
        let cmd = rd_u32(cmd_off)?;
        let cmdsize = rd_u32(cmd_off + 4)? as usize;
        if cmd == LC_SEGMENT_64 {
            let nsects = rd_u32(cmd_off + 64)? as usize;
            // sections follow the 72-byte segment_command_64.
            for i in 0..nsects {
                let s = cmd_off + 72 + i * 80; // sizeof(section_64) == 80
                let name_bytes = bytes.get(s..s + 16)?;
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
                if std::str::from_utf8(&name_bytes[..end]) == Ok(section) {
                    return Some(MachoSection {
                        name_off: s,
                        size: usize::try_from(rd_u64(s + 40)?).ok()?, // section_64.size
                        data_off: rd_u32(s + 48)? as usize,           // section_64.offset
                    });
                }
            }
        }
        cmd_off += cmdsize;
    }
    None
}

/// Re-apply an ad-hoc signature after the Mach-O has been edited.
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
fn codesign_adhoc(path: &Path) -> Result<()> {
    let status = Command::new("codesign")
        .arg("--force")
        .arg("--sign")
        .arg("-")
        .arg(path)
        .status()
        .context("running codesign")?;
    ensure!(
        status.success(),
        "codesign failed to ad-hoc sign the packed binary"
    );
    Ok(())
}

/// A fresh, process-unique temporary directory.
fn unique_tmpdir() -> Result<PathBuf> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("cargo-pack-sbom-{}-{n}", std::process::id()));
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}
