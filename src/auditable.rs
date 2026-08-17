// SPDX-License-Identifier: MIT

//! Preserving [`cargo-auditable`](https://github.com/rust-secure-code/cargo-auditable)
//! metadata across packing.
//!
//! `cargo auditable build` embeds a compressed dependency SBOM into a linker
//! section named `.dep-v0`, which `cargo audit bin` reads. Packing replaces the
//! application binary with the cargo-pack loader stub, so this module copies the
//! original's `.dep-v0` into the stub before the payload is attached. Two
//! mechanisms, chosen by the stub's object format:
//!
//! * **ELF and PE** (Linux, the BSDs, Solaris, Haiku, Windows, …): add the
//!   section in pure Rust (see [`crate::elf`]/[`crate::pe`]) — no external
//!   tools. A section is only present when there is real data.
//! * **Mach-O** (macOS): the stub reserves a fixed-size, neutrally-named slot
//!   ([`SLOT_SECTION`], created by `build.rs`); we overwrite it with the SBOM
//!   and rename it to `.dep-v0` in place. Signing is handled by the caller
//!   ([`crate::attach`]), which re-signs once after the payload is embedded too.
//!
//! Best-effort throughout: with no SBOM, missing tooling, or an oversized SBOM,
//! packing proceeds unchanged and the SBOM stays recoverable via `unpack`.

/// The section cargo-auditable uses for its embedded SBOM.
const DEP_SECTION: &str = ".dep-v0";

/// What happened to the original's cargo-auditable SBOM during packing.
pub enum Sbom {
    /// The original carried no `.dep-v0` section; nothing to do.
    Absent,
    /// The SBOM was embedded so `cargo audit bin` can read the packed binary.
    Embedded,
    /// The original has an SBOM but it could not be embedded; the reason is
    /// suitable for a user-facing note.
    Skipped(String),
}

/// Read the `.dep-v0` section from an object file, if present.
pub fn read_dep_section(binary: &[u8]) -> Option<Vec<u8>> {
    use object::{Object, ObjectSection};
    let file = object::File::parse(binary).ok()?;
    let section = file.section_by_name(DEP_SECTION)?;
    Some(section.data().ok()?.to_vec())
}

/// ELF/PE: return the stub with the SBOM added as a `.dep-v0` section (pure
/// Rust, no external tools), plus a status. Errors degrade to `Skipped`.
pub fn embed_for_elf_pe(stub: &[u8], original: &[u8]) -> (Vec<u8>, Sbom) {
    let Some(dep) = read_dep_section(original) else {
        return (stub.to_vec(), Sbom::Absent);
    };
    let result = if crate::elf::is_supported(stub) {
        crate::elf::add_section(stub, DEP_SECTION, &dep)
    } else if crate::pe::is_supported(stub) {
        crate::pe::add_section(stub, DEP_SECTION, &dep)
    } else {
        return (
            stub.to_vec(),
            Sbom::Skipped("unsupported executable format".into()),
        );
    };
    match result {
        Ok(bytes) => (bytes, Sbom::Embedded),
        Err(e) => (stub.to_vec(), Sbom::Skipped(format!("{e:#}"))),
    }
}

/// Mach-O: overwrite the reserved slot in `buf` with the SBOM and rename it to
/// `.dep-v0` in place (no signing — the caller signs once at the end).
pub fn embed_for_macho(buf: &mut [u8], original: &[u8]) -> Sbom {
    match read_dep_section(original) {
        Some(dep) => fill_slot(buf, &dep),
        None => Sbom::Absent,
    }
}

/// Neutral name of the slot reserved in a macOS stub by `build.rs`
/// (`ld64 -sectcreate __DATA __cgpkslot`), renamed to `.dep-v0` when populated.
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
const SLOT_SECTION: &str = "__cgpkslot";

/// Bytes reserved for an embedded SBOM. Must match `build.rs`'s `SLOT_LEN`.
#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
const SLOT_LEN: usize = 64 * 1024;

#[cfg(all(target_os = "macos", feature = "macos-auditable"))]
fn fill_slot(buf: &mut [u8], dep: &[u8]) -> Sbom {
    let Some(slot) = crate::macho::find_section(buf, SLOT_SECTION) else {
        return Sbom::Skipped("this build of cargo-pack has no SBOM slot".into());
    };
    if dep.len() > slot.size {
        return Sbom::Skipped(format!(
            "SBOM is {} bytes, larger than the {} KiB embed slot",
            dep.len(),
            SLOT_LEN / 1024
        ));
    }
    buf[slot.data_off..slot.data_off + dep.len()].copy_from_slice(dep);
    buf[slot.data_off + dep.len()..slot.data_off + slot.size].fill(0);
    crate::macho::rename_section(buf, &slot, DEP_SECTION);
    Sbom::Embedded
}

#[cfg(not(all(target_os = "macos", feature = "macos-auditable")))]
fn fill_slot(_buf: &mut [u8], _dep: &[u8]) -> Sbom {
    Sbom::Skipped(
        "embedding into a Mach-O binary requires macOS with the `macos-auditable` feature".into(),
    )
}
