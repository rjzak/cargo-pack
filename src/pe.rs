// SPDX-License-Identifier: MIT

//! Adding a section to a PE (Windows) executable, in pure safe Rust.
//!
//! A new section header is written into the padding that already exists after
//! the section table (within `SizeOfHeaders`), and the section's raw data is
//! appended at the end of the file, file-aligned. `NumberOfSections`,
//! `SizeOfImage`, and the PE checksum are updated accordingly. Existing sections
//! and their data do not move, so the image still loads. Placing the payload in
//! a real section (rather than a trailing overlay) also leaves the door open for
//! Authenticode signing, whose certificate table goes after the section data.
//!
//! Names are limited to PE's 8-byte inline field. If there is no room in the
//! header padding for another section entry, an error is returned so the caller
//! can fall back to an overlay.

use anyhow::{Result, ensure};

/// `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ`.
const SECTION_CHARACTERISTICS: u32 = 0x4000_0040;
const SECTION_HEADER_SIZE: usize = 40;

/// Whether `bytes` looks like a PE this module can extend.
pub fn is_supported(bytes: &[u8]) -> bool {
    pe_header_offset(bytes).is_some()
}

fn pe_header_offset(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew = rd_u32(bytes, 0x3c).ok()? as usize;
    (bytes.get(e_lfanew..e_lfanew + 4) == Some(b"PE\0\0")).then_some(e_lfanew)
}

/// Return `input` with a new section named `name` (≤ 8 bytes) containing `data`.
pub fn add_section(input: &[u8], name: &str, data: &[u8]) -> Result<Vec<u8>> {
    ensure!(name.len() <= 8, "PE section names are limited to 8 bytes");
    let pe = pe_header_offset(input).ok_or_else(|| anyhow::anyhow!("not a PE image"))?;

    let coff = pe + 4;
    let num_sections = rd_u16(input, coff + 2)? as usize;
    let size_opt = rd_u16(input, coff + 16)? as usize;
    let opt = coff + 20;

    let section_align = rd_u32(input, opt + 32)?;
    let file_align = rd_u32(input, opt + 36)?;
    let size_of_image = rd_u32(input, opt + 56)?;
    let size_of_headers = rd_u32(input, opt + 60)? as usize;
    ensure!(
        section_align != 0 && file_align != 0,
        "invalid PE alignments"
    );

    // Room for one more section header inside the header padding?
    let table = opt + size_opt;
    let new_hdr = table + num_sections * SECTION_HEADER_SIZE;
    ensure!(
        new_hdr + SECTION_HEADER_SIZE <= size_of_headers,
        "no room in the PE header for another section"
    );

    let raw_ptr = align_up(input.len() as u64, u64::from(file_align));
    let raw_size = align_up(data.len() as u64, u64::from(file_align));
    let virt_addr = size_of_image; // the image's current end is the next free RVA
    let new_size_of_image = align_up(
        u64::from(virt_addr) + data.len() as u64,
        u64::from(section_align),
    );

    let raw_ptr32 = u32::try_from(raw_ptr).map_err(|_| anyhow::anyhow!("PE file too large"))?;
    let raw_size32 = u32::try_from(raw_size).map_err(|_| anyhow::anyhow!("section too large"))?;
    let virt_size = u32::try_from(data.len()).map_err(|_| anyhow::anyhow!("section too large"))?;
    let new_size_of_image32 =
        u32::try_from(new_size_of_image).map_err(|_| anyhow::anyhow!("PE image too large"))?;
    let raw_ptr_usize = raw_ptr32 as usize;
    let raw_end = raw_ptr_usize + raw_size32 as usize;

    let mut out = input.to_vec();

    // Write the new section header into the padding after the section table.
    let mut hdr = [0u8; SECTION_HEADER_SIZE];
    hdr[..name.len()].copy_from_slice(name.as_bytes());
    hdr[8..12].copy_from_slice(&virt_size.to_le_bytes()); // VirtualSize
    hdr[12..16].copy_from_slice(&virt_addr.to_le_bytes()); // VirtualAddress
    hdr[16..20].copy_from_slice(&raw_size32.to_le_bytes()); // SizeOfRawData
    hdr[20..24].copy_from_slice(&raw_ptr32.to_le_bytes()); // PointerToRawData
    hdr[36..40].copy_from_slice(&SECTION_CHARACTERISTICS.to_le_bytes());
    out[new_hdr..new_hdr + SECTION_HEADER_SIZE].copy_from_slice(&hdr);

    // Update COFF/optional header fields.
    let new_num =
        u16::try_from(num_sections + 1).map_err(|_| anyhow::anyhow!("too many sections"))?;
    out[coff + 2..coff + 4].copy_from_slice(&new_num.to_le_bytes());
    out[opt + 56..opt + 60].copy_from_slice(&new_size_of_image32.to_le_bytes());
    // Invalidate the checksum (user-mode loaders don't verify it).
    out[opt + 64..opt + 68].copy_from_slice(&0u32.to_le_bytes());

    // Append the raw data, file-aligned.
    out.resize(raw_ptr_usize, 0);
    out.extend_from_slice(data);
    out.resize(raw_end, 0);

    Ok(out)
}

fn align_up(value: u64, align: u64) -> u64 {
    value.div_ceil(align) * align
}

fn rd_u16(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| anyhow::anyhow!("PE truncated at {o:#x}"))
}

fn rd_u32(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| anyhow::anyhow!("PE truncated at {o:#x}"))
}

// On Windows the test binary is itself a PE, so it doubles as the fixture.
#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use object::{Object, ObjectSection};

    #[test]
    fn adds_a_readable_section_to_this_test_binary() {
        let input = std::fs::read(std::env::current_exe().unwrap()).unwrap();

        let payload = b"cargo-pack payload bytes".repeat(300);
        let out = add_section(&input, ".cgpack", &payload).unwrap();

        let file = object::File::parse(&*out).expect("still a valid PE");
        let section = file.section_by_name(".cgpack").expect("section present");
        // VirtualSize is exact; the raw data is file-aligned (zero-padded).
        assert!(section.data().unwrap().starts_with(&payload));
    }
}
