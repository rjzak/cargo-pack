// SPDX-License-Identifier: MIT

//! Adding a section to a 64-bit little-endian ELF, in pure safe Rust.
//!
//! The technique is append-only: the payload, a fresh copy of the section-header
//! string table (with our name appended), and a rebuilt section-header table are
//! all written at EOF, and the ELF header's `e_shoff`/`e_shnum` are repointed at
//! the new table. Nothing already in the file moves, and no program header is
//! touched — so the binary still loads and runs exactly as before; only the
//! section table (which tools like `cargo audit bin` read) gains an entry.
//!
//! The added section is non-`ALLOC` (not mapped at runtime); the loader reads it
//! back from the file. Unsupported ELF shapes (32-bit, big-endian, extended
//! section indexing) return an error so the caller can fall back to an overlay.

use anyhow::{Result, ensure};

const EI_CLASS: usize = 4;
const ELFCLASS64: u8 = 2;
const EI_DATA: usize = 5;
const ELFDATA2LSB: u8 = 1;
const SHT_PROGBITS: u32 = 1;
const SHDR_SIZE: usize = 64;

/// Whether `bytes` is a 64-bit little-endian ELF this module can extend.
pub fn is_supported(bytes: &[u8]) -> bool {
    bytes.len() > EI_DATA
        && bytes.starts_with(b"\x7fELF")
        && bytes[EI_CLASS] == ELFCLASS64
        && bytes[EI_DATA] == ELFDATA2LSB
}

/// Return `input` with a new non-alloc section named `name` containing `data`.
pub fn add_section(input: &[u8], name: &str, data: &[u8]) -> Result<Vec<u8>> {
    ensure!(is_supported(input), "not a 64-bit little-endian ELF");

    let e_shoff = usize::try_from(rd_u64(input, 0x28)?)?;
    let e_shentsize = rd_u16(input, 0x3a)?;
    let e_shnum = rd_u16(input, 0x3c)? as usize;
    let e_shstrndx = rd_u16(input, 0x3e)? as usize;

    ensure!(
        e_shoff != 0 && e_shnum != 0,
        "ELF has no section header table"
    );
    ensure!(
        e_shentsize as usize == SHDR_SIZE,
        "unexpected ELF section header size"
    );
    ensure!(
        e_shstrndx < e_shnum,
        "extended section string index unsupported"
    );
    ensure!(
        e_shoff + e_shnum * SHDR_SIZE <= input.len(),
        "ELF section header table is out of bounds"
    );

    // Existing section-header string table (referenced only via e_shstrndx).
    let shstr_hdr = e_shoff + e_shstrndx * SHDR_SIZE;
    let shstr_off = usize::try_from(rd_u64(input, shstr_hdr + 0x18)?)?;
    let shstr_size = usize::try_from(rd_u64(input, shstr_hdr + 0x20)?)?;
    let old_shstr = input
        .get(shstr_off..shstr_off + shstr_size)
        .ok_or_else(|| anyhow::anyhow!("ELF .shstrtab is out of bounds"))?
        .to_vec();

    let mut out = input.to_vec();

    // 1) Payload data.
    pad_to(&mut out, 8);
    let data_off = out.len() as u64;
    out.extend_from_slice(data);

    // 2) A fresh .shstrtab = old table + our name, so old name offsets stay valid.
    pad_to(&mut out, 8);
    let new_shstr_off = out.len() as u64;
    let name_off =
        u32::try_from(old_shstr.len()).map_err(|_| anyhow::anyhow!(".shstrtab too large"))?;
    out.extend_from_slice(&old_shstr);
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    let new_shstr_size = (old_shstr.len() + name.len() + 1) as u64;

    // 3) Rebuilt section header table: old entries (with .shstrtab repointed) plus
    //    our new section.
    pad_to(&mut out, 8);
    let new_shoff = out.len() as u64;
    let table_start = out.len();
    out.extend_from_slice(&input[e_shoff..e_shoff + e_shnum * SHDR_SIZE]);
    let patch = table_start + e_shstrndx * SHDR_SIZE;
    out[patch + 0x18..patch + 0x20].copy_from_slice(&new_shstr_off.to_le_bytes());
    out[patch + 0x20..patch + 0x28].copy_from_slice(&new_shstr_size.to_le_bytes());

    let mut sh = [0u8; SHDR_SIZE];
    sh[0x00..0x04].copy_from_slice(&name_off.to_le_bytes()); // sh_name
    sh[0x04..0x08].copy_from_slice(&SHT_PROGBITS.to_le_bytes()); // sh_type
    // sh_flags (0x08) = 0 → not ALLOC, not mapped at runtime.
    sh[0x18..0x20].copy_from_slice(&data_off.to_le_bytes()); // sh_offset
    sh[0x20..0x28].copy_from_slice(&(data.len() as u64).to_le_bytes()); // sh_size
    sh[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
    out.extend_from_slice(&sh);

    // 4) Repoint the ELF header at the new table.
    out[0x28..0x30].copy_from_slice(&new_shoff.to_le_bytes());
    let new_shnum =
        u16::try_from(e_shnum + 1).map_err(|_| anyhow::anyhow!("too many ELF sections"))?;
    out[0x3c..0x3e].copy_from_slice(&new_shnum.to_le_bytes());

    Ok(out)
}

fn pad_to(out: &mut Vec<u8>, align: usize) {
    let rem = out.len() % align;
    if rem != 0 {
        out.resize(out.len() + (align - rem), 0);
    }
}

fn rd_u16(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| anyhow::anyhow!("ELF truncated at {o:#x}"))
}

fn rd_u64(b: &[u8], o: usize) -> Result<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| anyhow::anyhow!("ELF truncated at {o:#x}"))
}

// On ELF platforms the test binary is itself a 64-bit ELF, so it doubles as the
// fixture — no external file or env var needed.
#[cfg(all(
    test,
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "haiku",
    )
))]
mod tests {
    use super::*;
    use object::{Object, ObjectSection};

    #[test]
    fn adds_a_readable_section_to_this_test_binary() {
        let input = std::fs::read(std::env::current_exe().unwrap()).unwrap();

        let payload = b"cargo-pack payload bytes".repeat(300);
        let out = add_section(&input, ".cgpack", &payload).unwrap();

        // Only the ELF header's e_shoff/e_shnum change; everything after the
        // 64-byte header (program headers, segments) is untouched, so it still
        // loads and runs exactly as before.
        assert_eq!(out[64..input.len()], input[64..]);
        assert!(out.len() > input.len());
        // The object crate (what cargo audit bin uses) must parse it and find us.
        let file = object::File::parse(&*out).expect("still a valid ELF");
        let section = file.section_by_name(".cgpack").expect("section present");
        assert_eq!(section.data().unwrap(), &payload[..]);
    }
}
