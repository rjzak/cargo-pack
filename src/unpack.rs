// SPDX-License-Identifier: MIT

//! `cargo pack unpack`: restore a packed binary to its original state, and
//! `cargo pack info`: describe a binary without modifying it.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::cli::{InfoArgs, UnpackArgs};
use crate::format;
use crate::util::{entropy_calc, human_bytes, ratio_percent, write_executable};

pub fn unpack(args: UnpackArgs) -> Result<()> {
    let bytes =
        std::fs::read(&args.input).with_context(|| format!("reading {}", args.input.display()))?;
    if !format::is_packed(&bytes) {
        bail!("{} is not a packed binary", args.input.display());
    }

    let extracted = format::extract(&bytes)?;

    let output = args
        .output
        .unwrap_or_else(|| PathBuf::from(&extracted.name));
    if output.exists() && !args.force {
        bail!(
            "{} already exists; pass --force to overwrite or --output to choose another path",
            output.display()
        );
    }

    write_executable(&output, &extracted.original)?;
    let packed_entropy = entropy_calc(&bytes);
    let restored_entropy = entropy_calc(&extracted.original);
    println!(
        "cargo pack: restored {} -> {} ({}), \
         entropy {packed_entropy:.2} -> {restored_entropy:.2} bits/byte",
        args.input.display(),
        output.display(),
        human_bytes(extracted.original.len() as u64),
    );
    Ok(())
}

pub fn info(args: &InfoArgs) -> Result<()> {
    let bytes =
        std::fs::read(&args.input).with_context(|| format!("reading {}", args.input.display()))?;

    let Some(format_version) = format::packed_format_version(&bytes) else {
        bail!("{}: not packed", args.input.display());
    };
    let packed_len = bytes.len() as u64;

    // A binary packed by a newer cargo-pack can still be identified as packed
    // and its format version reported, even though this build cannot decode its
    // body. Report what we can rather than failing.
    if !format::is_supported_version(format_version) {
        println!("{}: packed", args.input.display());
        println!("  format version: {format_version}");
        println!("  packed size:    {}", human_bytes(packed_len));
        println!("  packed entropy: {:.2} bits/byte", entropy_calc(&bytes));
        println!(
            "  note:           packed with a newer format than this cargo-pack \
             understands; upgrade to inspect further"
        );
        return Ok(());
    }

    let extracted = format::extract(&bytes)?;
    let footer = &extracted.footer;
    let original_len = extracted.original.len() as u64;
    let ratio = ratio_percent(packed_len, original_len);

    println!("{}: packed", args.input.display());
    println!("  format version: {}", footer.format_version);
    println!("  algorithm:      {}", algorithm_name(footer.algorithm));
    println!("  original name:  {}", extracted.name);
    println!("  original size:  {}", human_bytes(original_len));
    println!(
        "  packed size:    {} ({ratio:.1}% of original)",
        human_bytes(packed_len)
    );
    println!(
        "  entropy:        {:.2} packed, {:.2} original",
        entropy_calc(&bytes),
        entropy_calc(&extracted.original),
    );
    println!("  crc32:          {:#010x}", footer.crc32);
    Ok(())
}

/// The kebab-case name a user types for an algorithm (e.g. `zstd`), via clap's
/// value-enum metadata, falling back to the debug name.
fn algorithm_name(algorithm: crate::compress::Algorithm) -> String {
    use clap::ValueEnum;
    algorithm
        .to_possible_value()
        .map_or_else(|| format!("{algorithm:?}"), |v| v.get_name().to_string())
}
