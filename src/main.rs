// SPDX-License-Identifier: MIT

#![doc = include_str!("../README.md")]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

//! `cargo-pack`: a cargo subcommand that builds and packs a binary into a
//! compressed, self-extracting executable — and can restore it again.
//!
//! The one binary plays two roles. Invoked normally (`cargo pack build`,
//! `cargo pack unpack`) it is the CLI. But `cargo pack build` produces packed
//! binaries by copying *this very executable* and appending a compressed
//! payload; when such a packed binary runs, [`main`] detects the trailing
//! footer and hands off to the [`stub`] loader instead of the CLI. That makes
//! the packer self-hosting: no separate stub crate, no cross-compilation.

mod attach;
mod auditable;
mod build;
mod cli;
mod compress;
mod elf;
mod format;
mod macho;
mod pe;
mod stub;
mod unpack;
mod util;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use cli::{Cargo, PackCommand};

fn main() -> ExitCode {
    let exe = std::env::current_exe().ok();

    // Loader role: if our own file carries a packed payload, extract and run it.
    if let Some(exe) = &exe
        && has_payload(exe)
    {
        if let Err(e) = stub::run(exe) {
            eprintln!("cargo-pack loader: {e:#}");
            return ExitCode::FAILURE;
        }
        // On Unix `stub::run` replaces the process via exec and never returns;
        // reaching here means a successful non-Unix launch.
        return ExitCode::SUCCESS;
    }

    // CLI role.
    match run_cli(exe) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cargo pack: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli(exe: Option<PathBuf>) -> Result<()> {
    let Cargo::Pack(pack) = Cargo::parse();
    match pack.command {
        PackCommand::Build(args) => {
            let exe = exe.context("could not locate the cargo-pack executable to use as a stub")?;
            let stub_bytes =
                std::fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?;
            // In CLI mode this executable is pristine, but strip any payload
            // defensively so we never nest a stub inside a stub.
            let stub_bytes = util::read_original(&stub_bytes)?;
            build::run(&args, &stub_bytes)
        }
        PackCommand::Unpack(args) => unpack::unpack(args),
        PackCommand::Info(args) => unpack::info(&args),
    }
}

/// Whether `path` carries a packed payload. The trailer sits at the container's
/// logical end — EOF for ELF/PE, or just before the code signature for a Mach-O
/// (whose payload lives inside `__LINKEDIT`) — so we let [`format::is_packed`]
/// locate it rather than assuming EOF.
fn has_payload(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|bytes| format::is_packed(&bytes))
}
