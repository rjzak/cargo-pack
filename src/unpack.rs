// SPDX-License-Identifier: MIT

//! `cargo pack unpack`: restore a packed binary to its original state, and
//! `cargo pack info`: describe a binary without modifying it.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::cli::{InfoArgs, UnpackArgs};
use crate::format;
use crate::util::{human_bytes, ratio_percent, write_executable};

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
    println!(
        "cargo pack: restored {} -> {} ({})",
        args.input.display(),
        output.display(),
        human_bytes(extracted.original.len() as u64),
    );
    Ok(())
}

pub fn info(args: &InfoArgs) -> Result<()> {
    let bytes =
        std::fs::read(&args.input).with_context(|| format!("reading {}", args.input.display()))?;

    if !format::is_packed(&bytes) {
        println!("{}: not packed", args.input.display());
        return Ok(());
    }

    let extracted = format::extract(&bytes)?;
    let packed_len = bytes.len() as u64;
    let original_len = extracted.original.len() as u64;
    let ratio = ratio_percent(packed_len, original_len);

    println!("{}: packed", args.input.display());
    println!("  original name:  {}", extracted.name);
    println!("  original size:  {}", human_bytes(original_len));
    println!(
        "  packed size:    {} ({ratio:.1}% of original)",
        human_bytes(packed_len)
    );
    println!("  crc32:          {:#010x}", extracted.crc32);
    Ok(())
}
