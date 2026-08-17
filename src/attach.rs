// SPDX-License-Identifier: MIT

//! Attaching the packer payload to the stub, per object format.
//!
//! * **Mach-O** (macOS): the payload is embedded inside `__LINKEDIT` (before the
//!   code signature) so nothing trails the signature — the packed binary is a
//!   valid, signable Mach-O. The stub's signature is removed, the SBOM slot and
//!   payload are written, then the whole thing is re-signed ad-hoc once.
//! * **ELF / PE**: the payload goes in a `.cgpack` section (pure Rust; see
//!   [`crate::elf`]/[`crate::pe`]), after any SBOM `.dep-v0` section, falling
//!   back to a trailing overlay if a section can't be added.

use anyhow::Result;

use crate::auditable::{self, Sbom};
use crate::compress::Algorithm;
use crate::{elf, format, macho, pe};

/// A packed binary plus what happened to its cargo-auditable SBOM.
pub struct Packed {
    pub bytes: Vec<u8>,
    pub sbom: Sbom,
}

/// Build a packed binary: compress `original`, preserve its SBOM into the stub,
/// and attach the payload in the way this stub's object format allows.
pub fn pack(
    stub: &[u8],
    original: &[u8],
    name: &str,
    algorithm: Algorithm,
    level: u8,
) -> Result<Packed> {
    let overlay = format::build_overlay(original, name, algorithm, level)?;

    if macho::is_macho(stub) {
        // Strip the stub's signature so __LINKEDIT ends the file, then write the
        // SBOM slot and the payload, then re-sign once.
        let mut buf = macho::remove_signature(stub)?;
        let sbom = auditable::embed_for_macho(&mut buf, original);
        macho::embed_payload(&mut buf, &overlay)?;
        let bytes = macho::codesign_adhoc(&buf)?;
        Ok(Packed { bytes, sbom })
    } else {
        let (stub, sbom) = auditable::embed_for_elf_pe(stub, original);
        let bytes = attach_payload_section(stub, &overlay);
        Ok(Packed { bytes, sbom })
    }
}

/// Put the overlay in a `.cgpack` section (ELF/PE), falling back to appending it
/// as a trailing overlay for object shapes the section writers don't handle.
fn attach_payload_section(stub: Vec<u8>, overlay: &[u8]) -> Vec<u8> {
    if elf::is_supported(&stub) {
        if let Ok(bytes) = elf::add_section(&stub, format::PAYLOAD_SECTION, overlay) {
            return bytes;
        }
    } else if pe::is_supported(&stub)
        && let Ok(bytes) = pe::add_section(&stub, format::PAYLOAD_SECTION, overlay)
    {
        return bytes;
    }
    let mut bytes = stub;
    bytes.extend_from_slice(overlay);
    bytes
}
