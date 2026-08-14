// SPDX-License-Identifier: MIT

//! The on-disk container format for a packed binary.
//!
//! A packed executable is laid out as:
//!
//! ```text
//! [ stub executable ]          the cargo-pack loader (self-hosting)
//! [ original name   ]          `name_len` UTF-8 bytes
//! [ compressed body ]          `compressed_len` bytes
//! [ footer body     ]          `body_len` bytes, schema depends on the version
//! [ trailer         ]          exactly TRAILER_SIZE bytes, at the very end
//! ```
//!
//! ## Versioning
//!
//! The **trailer** is a small, fixed-size block that must remain byte-compatible
//! *forever*: it holds the magic, the format version, and the length of the
//! footer body that precedes it. Because it is always the last [`TRAILER_SIZE`]
//! bytes of the file, any future build can locate it, read the version, and then
//! decide how to parse the rest — regardless of how the version-specific footer
//! body changes.
//!
//! The **footer body** carries the version-specific metadata (algorithm,
//! lengths, checksum, the cargo-pack version that produced the file, …). New
//! format versions add a new body schema and a new decoder branch, while old
//! decoders keep working on old files. Within a single version the body may also
//! grow: readers parse the fields they know from the front of the body and
//! ignore any trailing bytes, so additive changes need not bump the version.
//!
//! All fields are little-endian.

use anyhow::{Context, Result, bail, ensure};

use crate::compress::{self, Algorithm};

/// Marker at the start of the trailer. A pristine `cargo-pack` binary never ends
/// with these bytes, which is how we distinguish a packed binary from an
/// unpacked one.
pub const MAGIC: [u8; 8] = *b"CARGOPCK";

/// The format version this build writes. Bump this only when the footer body
/// schema changes incompatibly; additive changes are handled without a bump (see
/// the module docs).
pub const FORMAT_VERSION: u16 = 1;

/// Size of the fixed trailing block, in bytes. **This value and the trailer's
/// field layout must never change**, or existing binaries become unfindable.
///
/// Layout: `magic`(8) + `format_version`(2) + `body_len`(4) + `reserved`(2) = 16.
pub const TRAILER_SIZE: usize = 16;

/// Size of the version-1 footer body.
///
/// Layout: `algorithm`(2) + `name_len`(4) + `compressed_len`(8)
///       + `original_len`(8) + `crc32`(4) = 26.
const V1_BODY_SIZE: usize = 26;

/// The decoded metadata of a packed binary.
#[derive(Debug, Clone, Copy)]
pub struct Footer {
    /// The container format version the file was written with.
    pub format_version: u16,
    pub algorithm: Algorithm,
    pub name_len: u32,
    pub compressed_len: u64,
    pub original_len: u64,
    /// CRC32 of the *original* (uncompressed) bytes, for integrity checking.
    pub crc32: u32,
}

/// The recovered contents of a packed binary.
#[derive(Debug)]
pub struct Extracted {
    /// The original executable's file name, as recorded at pack time.
    pub name: String,
    /// The original, uncompressed executable bytes.
    pub original: Vec<u8>,
    /// The decoded metadata footer.
    pub footer: Footer,
}

/// Read a `u16`/`u32`/`u64` from a little-endian slice at `off`.
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}
fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

/// The fixed trailer, decoded.
struct Trailer {
    format_version: u16,
    body_len: usize,
}

/// Read and validate the fixed trailer from the end of `bytes`.
fn read_trailer(bytes: &[u8]) -> Option<Trailer> {
    if bytes.len() < TRAILER_SIZE {
        return None;
    }
    let t = &bytes[bytes.len() - TRAILER_SIZE..];
    if t[0..8] != MAGIC {
        return None;
    }
    Some(Trailer {
        format_version: read_u16(t, 8),
        body_len: read_u32(t, 10) as usize,
    })
}

/// Returns `true` if `bytes` ends with a valid trailer magic.
pub fn is_packed(bytes: &[u8]) -> bool {
    read_trailer(bytes).is_some()
}

/// The container format version `bytes` was packed with, if it is packed.
///
/// This works even for versions this build cannot fully decode, so callers can
/// report a useful message instead of a hard failure.
pub fn packed_format_version(bytes: &[u8]) -> Option<u16> {
    read_trailer(bytes).map(|t| t.format_version)
}

/// Whether this build can decode footers written with `format_version`.
pub fn is_supported_version(format_version: u16) -> bool {
    format_version == FORMAT_VERSION
}

/// Serialize the version-1 footer body.
fn encode_v1_body(footer: &Footer) -> [u8; V1_BODY_SIZE] {
    let mut b = [0u8; V1_BODY_SIZE];
    b[0..2].copy_from_slice(&footer.algorithm.to_u16().to_le_bytes());
    b[2..6].copy_from_slice(&footer.name_len.to_le_bytes());
    b[6..14].copy_from_slice(&footer.compressed_len.to_le_bytes());
    b[14..22].copy_from_slice(&footer.original_len.to_le_bytes());
    b[22..26].copy_from_slice(&footer.crc32.to_le_bytes());
    b
}

/// Parse the version-1 footer body from the front of `body` (which may be longer
/// than [`V1_BODY_SIZE`] if a later revision appended fields).
fn decode_v1_body(body: &[u8], format_version: u16) -> Result<Footer> {
    ensure!(
        body.len() >= V1_BODY_SIZE,
        "footer body is too short for format version 1"
    );
    let algorithm = Algorithm::from_u16(read_u16(body, 0))
        .context("unknown compression algorithm in footer")?;
    Ok(Footer {
        format_version,
        algorithm,
        name_len: read_u32(body, 2),
        compressed_len: read_u64(body, 6),
        original_len: read_u64(body, 14),
        crc32: read_u32(body, 22),
    })
}

/// Serialize the fixed trailer.
fn encode_trailer(format_version: u16, body_len: u32) -> [u8; TRAILER_SIZE] {
    let mut t = [0u8; TRAILER_SIZE];
    t[0..8].copy_from_slice(&MAGIC);
    t[8..10].copy_from_slice(&format_version.to_le_bytes());
    t[10..14].copy_from_slice(&body_len.to_le_bytes());
    // t[14..16] reserved, left zero.
    t
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
        format_version: FORMAT_VERSION,
        algorithm,
        name_len,
        compressed_len: compressed.len() as u64,
        original_len: original.len() as u64,
        crc32,
    };
    let body = encode_v1_body(&footer);
    let body_len = u32::try_from(body.len()).expect("v1 body length fits in u32");
    let trailer = encode_trailer(FORMAT_VERSION, body_len);

    let mut out = Vec::with_capacity(
        stub.len() + name_bytes.len() + compressed.len() + body.len() + TRAILER_SIZE,
    );
    out.extend_from_slice(stub);
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&compressed);
    out.extend_from_slice(&body);
    out.extend_from_slice(&trailer);
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
    let trailer = read_trailer(bytes).context("not a packed binary (bad magic)")?;

    if !is_supported_version(trailer.format_version) {
        bail!(
            "this binary was packed with cargo-pack format version {}, but this build only \
             understands version {FORMAT_VERSION}; upgrade cargo-pack to work with it",
            trailer.format_version
        );
    }

    let body_end = bytes.len() - TRAILER_SIZE;
    let body_start = body_end
        .checked_sub(trailer.body_len)
        .context("footer body length is larger than the file")?;
    let footer = decode_v1_body(&bytes[body_start..body_end], trailer.format_version)?;

    let compressed_len = usize::try_from(footer.compressed_len)
        .context("compressed length does not fit in memory")?;
    let payload_end = body_start;
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
        footer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A stand-in for the loader stub. `is_packed` must be false for it alone.
    const STUB: &[u8] = b"\x7fELF fake stub bytes that do not end in the magic";

    fn roundtrip(algo: Algorithm) {
        let original = b"the original executable payload, repeated. ".repeat(500);
        let packed = pack(STUB, &original, "my-bin", algo, compress::DEFAULT_LEVEL).unwrap();

        assert!(is_packed(&packed));
        assert!(!is_packed(STUB));
        assert!(packed.starts_with(STUB), "stub must be preserved verbatim");
        assert_eq!(packed_format_version(&packed), Some(FORMAT_VERSION));

        let extracted = extract(&packed).unwrap();
        assert_eq!(extracted.name, "my-bin");
        assert_eq!(extracted.original, original);
        assert_eq!(extracted.footer.crc32, crc32fast::hash(&original));
        assert_eq!(extracted.footer.format_version, FORMAT_VERSION);

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
    fn future_format_version_is_rejected_gracefully() {
        // Take a valid v1 binary and bump the trailer's version field.
        let mut packed = pack(STUB, b"payload", "bin", Algorithm::Zstd, 50).unwrap();
        let ver_off = packed.len() - TRAILER_SIZE + 8;
        packed[ver_off..ver_off + 2].copy_from_slice(&999u16.to_le_bytes());

        // Still detectable and its version still readable...
        assert!(is_packed(&packed));
        assert_eq!(packed_format_version(&packed), Some(999));
        assert!(!is_supported_version(999));
        // ...but decoding fails with a clear, non-panicking error.
        let err = extract(&packed).unwrap_err().to_string();
        assert!(
            err.contains("format version 999"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn body_may_grow_within_a_version() {
        // A future v1 revision could append fields to the body. Simulate that by
        // inserting extra bytes between the body and the trailer and growing the
        // recorded body length; a current reader must still parse the prefix.
        let packed = pack(STUB, b"some payload here", "bin", Algorithm::Zstd, 50).unwrap();
        let (trailer_start, body_len) = {
            let t = read_trailer(&packed).unwrap();
            (packed.len() - TRAILER_SIZE, t.body_len)
        };

        let mut grown = packed[..trailer_start].to_vec();
        grown.extend_from_slice(&[0xAB; 8]); // pretend-appended future fields
        let mut trailer = packed[trailer_start..].to_vec();
        let new_body_len = u32::try_from(body_len + 8).unwrap();
        trailer[10..14].copy_from_slice(&new_body_len.to_le_bytes());
        grown.extend_from_slice(&trailer);

        let extracted = extract(&grown).unwrap();
        assert_eq!(extracted.name, "bin");
        assert_eq!(extracted.original, b"some payload here");
    }

    #[test]
    fn corrupt_payload_is_rejected() {
        let original = b"abcdefghij".repeat(100);
        let mut packed = pack(STUB, &original, "bin", Algorithm::Zstd, 50).unwrap();
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
        assert_eq!(packed_format_version(STUB), None);
    }
}
