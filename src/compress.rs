// SPDX-License-Identifier: MIT

//! Compression algorithms available to the packer.
//!
//! New algorithms are added here and wired into [`Algorithm`]; the container
//! format stores the numeric id so packed binaries stay self-describing. The
//! numeric ids are part of the on-disk format and must remain stable and
//! append-only across releases.
//!
//! Compression effort is exposed to users on a single, uniform scale
//! ([`MIN_LEVEL`]`..=`[`MAX_LEVEL`], i.e. 0–100) rather than each codec's native
//! range. `0` means "fastest / least compression" and `100` means "smallest /
//! most compression"; [`native_level`] maps that dial onto whatever range the
//! chosen algorithm actually uses.

use std::io::{Read, Write};

use anyhow::{Result, ensure};

/// Lowest compression effort: fastest, least compression.
pub const MIN_LEVEL: u8 = 0;
/// Highest compression effort: slowest, smallest output.
pub const MAX_LEVEL: u8 = 100;
/// Default effort: strong compression without paying for the last, slow few
/// percent that maxing out each codec would cost.
pub const DEFAULT_LEVEL: u8 = 90;

/// A supported compression algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Algorithm {
    /// No compression; the payload is stored verbatim. A testing aid, so it is
    /// only offered when packing with a debug build of `cargo-pack`.
    #[cfg_attr(not(debug_assertions), value(hide = true))]
    Store,
    /// Zstandard. Excellent ratio with very fast decompression; the default.
    Zstd,
    /// DEFLATE (raw, no zlib/gzip wrapper). Ubiquitous, modest ratio.
    Deflate,
    /// LZ4, a fast Lempel–Ziv codec. Weakest ratio, quickest to pack/unpack.
    Lz4,
    /// XZ / LZMA2. Strongest ratio, slowest to pack.
    Xz,
    /// bzip2. Strong ratio via Burrows–Wheeler; slower than zstd.
    Bzip2,
}

impl Algorithm {
    /// The stable on-disk id for this algorithm.
    pub fn to_u16(self) -> u16 {
        match self {
            Algorithm::Store => 0,
            Algorithm::Zstd => 1,
            Algorithm::Deflate => 2,
            Algorithm::Lz4 => 3,
            Algorithm::Xz => 4,
            Algorithm::Bzip2 => 5,
        }
    }

    /// Decode an algorithm from its on-disk id.
    pub fn from_u16(v: u16) -> Option<Algorithm> {
        match v {
            0 => Some(Algorithm::Store),
            1 => Some(Algorithm::Zstd),
            2 => Some(Algorithm::Deflate),
            3 => Some(Algorithm::Lz4),
            4 => Some(Algorithm::Xz),
            5 => Some(Algorithm::Bzip2),
            _ => None,
        }
    }

    /// This algorithm's native level range as `(low, high)`, or `None` if it has
    /// no tunable level (`Store`, `Lz4`).
    fn native_range(self) -> Option<(u32, u32)> {
        match self {
            Algorithm::Store | Algorithm::Lz4 => None,
            // zstd also supports negative "fast" levels, but this is a size
            // packer, so we only expose 1..=22.
            Algorithm::Zstd => Some((1, 22)),
            Algorithm::Deflate | Algorithm::Xz => Some((0, 9)),
            Algorithm::Bzip2 => Some((1, 9)),
        }
    }

    /// Map a uniform effort `level` (0–100) onto this algorithm's native level.
    ///
    /// Returns `None` for algorithms without a tunable level.
    fn native_level(self, level: u8) -> Option<u32> {
        let (lo, hi) = self.native_range()?;
        let level = u32::from(level.min(MAX_LEVEL));
        // Round to nearest within [lo, hi]; level 0 -> lo, level 100 -> hi.
        Some(lo + (level * (hi - lo) + 50) / 100)
    }

    /// Whether this algorithm may be *selected* for packing in the current
    /// build. `Store` is a testing aid restricted to debug builds; every
    /// algorithm can still be *decoded* regardless of build profile so that
    /// existing packed binaries always unpack.
    pub fn selectable(self) -> bool {
        cfg!(debug_assertions) || !matches!(self, Algorithm::Store)
    }
}

/// Compress `data` with `algorithm` at the given uniform effort `level` (0–100).
pub fn compress(algorithm: Algorithm, data: &[u8], level: u8) -> Result<Vec<u8>> {
    // Every codec below has a native level; `unwrap_or_default` covers the
    // `Store`/`Lz4` cases, which ignore the value entirely.
    let native = algorithm.native_level(level).unwrap_or_default();
    match algorithm {
        Algorithm::Store => Ok(data.to_vec()),
        // zstd's API is signed; our native range (1..=22) is always small and
        // non-negative, so this conversion never fails.
        Algorithm::Zstd => {
            let level = i32::try_from(native).expect("zstd native level fits in i32");
            Ok(zstd::encode_all(data, level)?)
        }
        Algorithm::Deflate => {
            let mut enc =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(native));
            enc.write_all(data)?;
            Ok(enc.finish()?)
        }
        Algorithm::Lz4 => {
            // Prepends the uncompressed length so decode needs no external hint.
            Ok(lz4_flex::compress_prepend_size(data))
        }
        Algorithm::Xz => {
            let mut enc = xz2::write::XzEncoder::new(Vec::new(), native);
            enc.write_all(data)?;
            Ok(enc.finish()?)
        }
        Algorithm::Bzip2 => {
            let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(native));
            enc.write_all(data)?;
            Ok(enc.finish()?)
        }
    }
}

/// Decompress `data` that was produced by [`compress`] with `algorithm`.
///
/// `original_len` is a hint used to pre-size the output buffer; correctness does
/// not depend on it. The compression level is not needed to decompress.
pub fn decompress(algorithm: Algorithm, data: &[u8], original_len: usize) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Store => Ok(data.to_vec()),
        Algorithm::Zstd => {
            let mut out = Vec::with_capacity(original_len);
            zstd::stream::copy_decode(data, &mut out)?;
            Ok(out)
        }
        Algorithm::Deflate => {
            let mut out = Vec::with_capacity(original_len);
            flate2::read::DeflateDecoder::new(data).read_to_end(&mut out)?;
            Ok(out)
        }
        Algorithm::Lz4 => lz4_flex::decompress_size_prepended(data)
            .map_err(|e| anyhow::anyhow!("lz4 decompression failed: {e}")),
        Algorithm::Xz => {
            let mut out = Vec::with_capacity(original_len);
            xz2::read::XzDecoder::new(data).read_to_end(&mut out)?;
            Ok(out)
        }
        Algorithm::Bzip2 => {
            let mut out = Vec::with_capacity(original_len);
            bzip2::read::BzDecoder::new(data).read_to_end(&mut out)?;
            Ok(out)
        }
    }
}

/// Validate a uniform effort `level`, returning a clear error rather than
/// letting a codec fail cryptically. Enforced independently of clap so the
/// library API is safe on its own.
pub fn validate_level(level: u8) -> Result<()> {
    ensure!(
        (MIN_LEVEL..=MAX_LEVEL).contains(&level),
        "compression level {level} is out of range ({MIN_LEVEL}..={MAX_LEVEL})"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Algorithm> {
        vec![
            Algorithm::Store,
            Algorithm::Zstd,
            Algorithm::Deflate,
            Algorithm::Lz4,
            Algorithm::Xz,
            Algorithm::Bzip2,
        ]
    }

    #[test]
    fn every_algorithm_roundtrips_across_the_scale() {
        let data = b"Lempel-Ziv and friends, repeated for compressibility. ".repeat(400);
        for algo in all() {
            for level in [MIN_LEVEL, DEFAULT_LEVEL, MAX_LEVEL] {
                let packed = compress(algo, &data, level).unwrap();
                let back = decompress(algo, &packed, data.len()).unwrap();
                assert_eq!(back, data, "roundtrip failed for {algo:?} @ {level}");
            }
        }
    }

    #[test]
    fn scale_maps_to_native_endpoints() {
        // Extremes of the uniform scale hit the extremes of each native range.
        assert_eq!(Algorithm::Zstd.native_level(MIN_LEVEL), Some(1));
        assert_eq!(Algorithm::Zstd.native_level(MAX_LEVEL), Some(22));
        assert_eq!(Algorithm::Xz.native_level(MIN_LEVEL), Some(0));
        assert_eq!(Algorithm::Xz.native_level(MAX_LEVEL), Some(9));
        assert_eq!(Algorithm::Bzip2.native_level(MAX_LEVEL), Some(9));
        // Algorithms without a tunable level report none.
        assert_eq!(Algorithm::Lz4.native_level(DEFAULT_LEVEL), None);
        assert_eq!(Algorithm::Store.native_level(DEFAULT_LEVEL), None);
    }

    #[test]
    fn ids_are_stable_and_unique() {
        for algo in all() {
            assert_eq!(Algorithm::from_u16(algo.to_u16()), Some(algo));
        }
    }
}
