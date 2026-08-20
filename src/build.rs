// SPDX-License-Identifier: MIT

//! `cargo pack build`: build the project with cargo, then pack each produced
//! binary in place.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::attach;
use crate::auditable;
use crate::cli::BuildArgs;
use crate::compress;
use crate::util::{self, human_bytes, read_original};

pub fn run(args: &BuildArgs, stub: &[u8]) -> Result<()> {
    let level = args.level;
    compress::validate_level(level)?;

    let executables = cargo_build(&args.cargo_args)?;
    if executables.is_empty() {
        println!("cargo pack: build produced no binaries to pack.");
        return Ok(());
    }

    for exe in &executables {
        pack_in_place(exe, stub, args.algorithm, level)?;
    }
    Ok(())
}

/// Run `cargo build`, streaming its diagnostics to the terminal, and return the
/// paths of the executables it produced.
fn cargo_build(cargo_args: &[String]) -> Result<Vec<PathBuf>> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let mut cmd = Command::new(cargo);
    cmd.arg("build")
        // Machine-readable artifacts on stdout, human diagnostics on stderr.
        .arg("--message-format=json-render-diagnostics")
        .args(cargo_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd.spawn().context("failed to launch cargo")?;
    let stdout = child.stdout.take().expect("piped stdout");

    let mut executables = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.context("reading cargo output")?;
        if line.is_empty() {
            continue;
        }
        // Be tolerant: any line we can't understand is simply skipped.
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if msg["reason"] != "compiler-artifact" {
            continue;
        }
        let Some(exe) = msg["executable"].as_str() else {
            continue;
        };
        let is_bin = msg["target"]["kind"]
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|k| k == "bin"));
        if is_bin {
            let path = PathBuf::from(exe);
            if !executables.contains(&path) {
                executables.push(path);
            }
        }
    }

    let status = child.wait().context("waiting for cargo")?;
    if !status.success() {
        bail!("cargo build failed");
    }

    Ok(executables)
}

/// Replace a single executable on disk with its packed form.
fn pack_in_place(
    exe: &std::path::Path,
    stub: &[u8],
    algorithm: compress::Algorithm,
    level: u8,
) -> Result<()> {
    let bytes = std::fs::read(exe).with_context(|| format!("reading {}", exe.display()))?;
    let original = read_original(&bytes)?;
    let original_len = original.len() as u64;

    let name = exe.file_name().map_or_else(
        || "program".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );

    // Compress and attach the payload, carrying any cargo-auditable SBOM from
    // the original into the packed binary; SBOM handling is best-effort.
    let packed = attach::pack(stub, &original, &name, algorithm, level)?;
    let sbom = match &packed.sbom {
        auditable::Sbom::Embedded => ", cargo-auditable SBOM preserved",
        auditable::Sbom::Absent => "",
        auditable::Sbom::Skipped(reason) => {
            eprintln!(
                "cargo pack: note: {name}: cargo-auditable SBOM not embedded ({reason}); \
                 recover it with `cargo pack unpack`"
            );
            ""
        }
    };
    let packed = packed.bytes;
    let packed_len = packed.len() as u64;

    util::write_executable(exe, &packed)?;

    let ratio = util::ratio_percent(packed_len, original_len);
    let original_entropy = util::entropy_calc(&original);
    let packed_entropy = util::entropy_calc(&packed);
    println!(
        "cargo pack: {name}: {} -> {} ({ratio:.1}% of original), \
         entropy {original_entropy:.2} -> {packed_entropy:.2} bits/byte{sbom}",
        human_bytes(original_len),
        human_bytes(packed_len),
    );
    Ok(())
}
