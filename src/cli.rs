// SPDX-License-Identifier: MIT

//! Command-line interface for the `cargo pack` subcommand.
//!
//! Cargo invokes `cargo pack build` as `cargo-pack pack build`, so the argument
//! parser follows the standard cargo-subcommand shape: a top-level `cargo`
//! command with a single `pack` subcommand underneath it.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::compress::{self, Algorithm};

/// Top-level entry point matching how cargo invokes us.
#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    /// Build and pack a binary into a compressed, self-extracting executable.
    Pack(PackArgs),
}

#[derive(Args)]
pub struct PackArgs {
    #[command(subcommand)]
    pub command: PackCommand,
}

#[derive(Subcommand)]
pub enum PackCommand {
    /// Build the project with cargo, then pack the resulting binaries in place.
    Build(BuildArgs),
    /// Restore a packed binary to its original, unpacked state.
    Unpack(UnpackArgs),
    /// Report whether a binary is packed, and with what.
    Info(InfoArgs),
}

#[derive(Args)]
#[command(after_help = "\
Note: `cargo pack`'s own options (--algorithm, --level) must come BEFORE the \
forwarded cargo arguments, since everything after the first cargo argument is \
passed through to `cargo build` verbatim.

    cargo pack build --algorithm zstd --level 90 --release")]
pub struct BuildArgs {
    /// Compression algorithm to use.
    #[arg(long, value_enum, default_value_t = Algorithm::Zstd)]
    pub algorithm: Algorithm,

    /// Compression effort from 0 (fastest, least compression) to 100
    /// (smallest, most compression). Mapped onto each algorithm's native range;
    /// ignored by algorithms without a tunable level (lz4, store).
    #[arg(
        long,
        default_value_t = compress::DEFAULT_LEVEL,
        value_parser = clap::value_parser!(u8).range(i64::from(compress::MIN_LEVEL)..=i64::from(compress::MAX_LEVEL)),
    )]
    pub level: u8,

    /// Arguments forwarded verbatim to `cargo build` (e.g. `--release`,
    /// `--target`, `-p`, `--features`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub cargo_args: Vec<String>,
}

#[derive(Args)]
pub struct UnpackArgs {
    /// The packed binary to restore.
    pub input: PathBuf,

    /// Where to write the restored binary. Defaults to the original file name
    /// recorded at pack time, in the current directory.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Overwrite the output file if it already exists.
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct InfoArgs {
    /// The binary to inspect.
    pub input: PathBuf,
}
