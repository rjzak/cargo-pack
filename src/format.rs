// SPDX-License-Identifier: MIT

//! The on-disk container format for a packed binary.
//!
//! A packed executable is laid out as:
//!
//! ```text
//! [ stub executable ]          the cargo-pack loader (self-hosting)
//! [ original name   ]          `name_len` UTF-8 bytes
//! [ compressed body ]          `compressed_len` bytes
//! [ footer          ]          exactly FOOTER_SIZE bytes, at the very end
//! ```
//!
//! The footer sits at the end of the file so the loader can find the payload by
//! reading a fixed number of trailing bytes and working backwards. All footer
//! fields are little-endian.

use anyhow::{Context, Result, bail, ensure};

use crate::compress::{self, Algorithm};

/// Marker at the start of the footer. A pristine `cargo-pack` binary never ends
/// with these bytes, which is how we distinguish a packed binary from an
/// unpacked one.
pub const MAGIC: [u8; 8] = *b"CARGOPCK";

/// Current container-format version.
pub const VERSION: u16 = 1;

/// Size of the fixed trailing footer, in bytes.
///
/// Layout: `magic`(8) + `version`(2) + `algorithm`(2) + `name_len`(4)
///       + `compressed_len`(8) + `original_len`(8) + `crc32`(4) + `reserved`(4) = 40.
pub const FOOTER_SIZE: usize = 40;

/// The decoded trailing footer of a packed binary.
#[derive(Debug, Clone, Copy)]
pub struct Footer {
    pub version: u16,
    pub algorithm: Algorithm,
    pub name_len: u32,
    pub compressed_len: u64,
    pub original_len: u64,
    /// CRC32 of the *original* (uncompressed) bytes, for integrity checking.
    pub crc32: u32,
}

impl Footer {
    /// Serialize the footer into its fixed-size on-disk form.
    fn encode(&self) -> [u8; FOOTER_SIZE] {
        let mut buf = [0u8; FOOTER_SIZE];
        buf[0..8].copy_from_slice(&MAGIC);
        buf[8..10].copy_from_slice(&self.version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.algorithm.to_u16().to_le_bytes());
        buf[12..16].copy_from_slice(&self.name_len.to_le_bytes());
        buf[16..24].copy_from_slice(&self.compressed_len.to_le_bytes());
        buf[24..32].copy_from_slice(&self.original_len.to_le_bytes());
        buf[32..36].copy_from_slice(&self.crc32.to_le_bytes());
        // buf[36..40] reserved, left zero.
        buf
    }

    /// Parse a footer from its fixed-size on-disk form, validating the magic.
    fn decode(buf: &[u8; FOOTER_SIZE]) -> Result<Footer> {
        ensure!(buf[0..8] == MAGIC, "not a packed binary (bad magic)");
        let version = u16::from_le_bytes(buf[8..10].try_into().unwrap());
        ensure!(
            version == VERSION,
            "unsupported pack format version {version} (this build understands {VERSION})"
        );
        let algorithm = Algorithm::from_u16(u16::from_le_bytes(buf[10..12].try_into().unwrap()))
            .context("unknown compression algorithm in footer")?;
        Ok(Footer {
            version,
            algorithm,
            name_len: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            compressed_len: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            original_len: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            crc32: u32::from_le_bytes(buf[32..36].try_into().unwrap()),
        })
    }
}

/// The recovered contents of a packed binary.
pub struct Extracted {
    /// The original executable's file name, as recorded at pack time.
    pub name: String,
    /// The original, uncompressed executable bytes.
    pub original: Vec<u8>,
    /// CRC32 of `original`, already verified against the footer.
    pub crc32: u32,
}

/// Returns `true` if `bytes` ends with a valid-looking footer magic.
pub fn is_packed(bytes: &[u8]) -> bool {
    bytes.len() >= FOOTER_SIZE
        && bytes[bytes.len() - FOOTER_SIZE..bytes.len() - FOOTER_SIZE + 8] == MAGIC
}

/// Build the full byte image of a packed binary from a stub, the original
/// executable, and packing options.
pub fn pack(
    stub: &[u8],
    original: &[u8],
    name: &str,
    algorithm: Algorithm,
    level: u8,
) -> Result<Vec<u8>> {
    let name_bytes = name.as_bytes();
    let name_len = u32::try_from(name_bytes.len()).context("original file name is too long")?;

    let compressed = compress::compress(algorithm, original, level)
        .context("compressing the original executable")?;
    let crc32 = crc32fast::hash(original);

    let footer = Footer {
        version: VERSION,
        algorithm,
        name_len,
        compressed_len: compressed.len() as u64,
        original_len: original.len() as u64,
        crc32,
    };

    let mut out =
        Vec::with_capacity(stub.len() + name_bytes.len() + compressed.len() + FOOTER_SIZE);
    out.extend_from_slice(stub);
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&compressed);
    out.extend_from_slice(&footer.encode());
    Ok(out)
}

/// Byte offsets of the payload sections within a packed file, derived from the
/// footer without decompressing anything.
struct Layout {
    footer: Footer,
    name_start: usize,
    payload_start: usize,
    payload_end: usize,
}

fn layout(bytes: &[u8]) -> Result<Layout> {
    ensure!(
        bytes.len() >= FOOTER_SIZE,
        "file is too small to be a packed binary"
    );

    let footer_start = bytes.len() - FOOTER_SIZE;
    let footer_buf: &[u8; FOOTER_SIZE] = bytes[footer_start..].try_into().unwrap();
    let footer = Footer::decode(footer_buf)?;

    let compressed_len = usize::try_from(footer.compressed_len)
        .context("compressed length does not fit in memory")?;
    let payload_end = footer_start;
    let payload_start = payload_end
        .checked_sub(compressed_len)
        .context("footer claims a compressed length larger than the file")?;
    let name_start = payload_start
        .checked_sub(footer.name_len as usize)
        .context("footer claims a name length larger than the file")?;

    Ok(Layout {
        footer,
        name_start,
        payload_start,
        payload_end,
    })
}

/// Read the footer and original file name without decompressing the payload.
///
/// The loader uses this to check its extraction cache cheaply before deciding
/// whether the expensive [`extract`] is needed.
pub fn peek(bytes: &[u8]) -> Result<(Footer, String)> {
    let l = layout(bytes)?;
    let name = String::from_utf8(bytes[l.name_start..l.payload_start].to_vec())
        .context("original file name is not valid UTF-8")?;
    Ok((l.footer, name))
}

/// Recover the original executable from the full bytes of a packed binary.
pub fn extract(bytes: &[u8]) -> Result<Extracted> {
    let l = layout(bytes)?;
    let footer = l.footer;

    let name = String::from_utf8(bytes[l.name_start..l.payload_start].to_vec())
        .context("original file name is not valid UTF-8")?;
    let compressed = &bytes[l.payload_start..l.payload_end];

    // Capacity hint only; a value too large for usize just means "don't
    // preallocate", so a saturating fallback is fine here.
    let size_hint = usize::try_from(footer.original_len).unwrap_or(0);
    let original = compress::decompress(footer.algorithm, compressed, size_hint)
        .context("decompressing the payload")?;
    ensure!(
        original.len() as u64 == footer.original_len,
        "decompressed size mismatch: got {}, expected {}",
        original.len(),
        footer.original_len
    );

    let crc32 = crc32fast::hash(&original);
    if crc32 != footer.crc32 {
        bail!(
            "integrity check failed: crc32 {crc32:#010x} does not match footer {:#010x}",
            footer.crc32
        );
    }

    Ok(Extracted {
        name,
        original,
        crc32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A stand-in for the loader stub. `is_packed` must be false for it alone.
    const STUB: &[u8] = b"\x7fELF fake stub bytes that do not end in the magic";

    fn roundtrip(algo: Algorithm) {
        let original = b"the original executable payload, repeated. ".repeat(500);
        let packed = pack(
            STUB,
            &original,
            "my-bin",
            algo,
            crate::compress::DEFAULT_LEVEL,
        )
        .unwrap();

        assert!(is_packed(&packed));
        assert!(!is_packed(STUB));
        assert!(packed.starts_with(STUB), "stub must be preserved verbatim");

        let extracted = extract(&packed).unwrap();
        assert_eq!(extracted.name, "my-bin");
        assert_eq!(extracted.original, original);
        assert_eq!(extracted.crc32, crc32fast::hash(&original));

        let (footer, name) = peek(&packed).unwrap();
        assert_eq!(name, "my-bin");
        assert_eq!(footer.algorithm, algo);
        assert_eq!(footer.original_len, original.len() as u64);
    }

    #[test]
    fn roundtrip_zstd() {
        roundtrip(Algorithm::Zstd);
    }

    #[test]
    fn roundtrip_store() {
        roundtrip(Algorithm::Store);
    }

    #[test]
    fn corrupt_payload_is_rejected() {
        let original = b"abcdefghij".repeat(100);
        let mut packed = pack(STUB, &original, "bin", Algorithm::Zstd, 3).unwrap();
        // Flip a byte inside the compressed payload region.
        let idx = STUB.len() + 4;
        packed[idx] ^= 0xff;
        assert!(extract(&packed).is_err());
    }

    #[test]
    fn not_packed_is_detected() {
        assert!(extract(STUB).is_err());
        assert!(!is_packed(STUB));
        assert!(!is_packed(&[]));
    }
}
