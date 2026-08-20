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
        // cargo prints one JSON object per line. Rather than pull in a JSON
        // parser we scan each line for just the three fields we need; anything
        // we don't recognise is simply skipped.
        if !line.contains("\"reason\":\"compiler-artifact\"") || !is_bin_artifact(&line) {
            continue;
        }
        let Some(exe) = json_string_field(&line, "executable") else {
            // A non-runnable artifact (a library) or an explicit `null`.
            continue;
        };
        let path = PathBuf::from(exe);
        if !executables.contains(&path) {
            executables.push(path);
        }
    }

    let status = child.wait().context("waiting for cargo")?;
    if !status.success() {
        bail!("cargo build failed");
    }

    Ok(executables)
}

/// Whether an artifact line describes a `bin` target, i.e. its `target.kind`
/// array contains the element `"bin"`. This mirrors cargo's own notion of a
/// runnable binary and excludes examples, tests, and libraries.
fn is_bin_artifact(line: &str) -> bool {
    let Some((_, rest)) = line.split_once("\"kind\":[") else {
        return false;
    };
    let Some(end) = rest.find(']') else {
        return false;
    };
    rest[..end]
        .split(',')
        .any(|elem| elem.trim().trim_matches('"') == "bin")
}

/// Extract the string value that immediately follows `"<key>":` in `line`,
/// decoding JSON escapes. Returns `None` when the key is absent or its value is
/// not a string (e.g. `null`).
///
/// This is a deliberately small, single-field reader rather than a JSON parser.
/// It only needs to cope with what cargo actually emits — most importantly the
/// `\\` and `\"` escapes in Windows executable paths — so the surrogate-pair
/// side of `\uXXXX` is left unhandled; cargo never emits those in a path.
fn json_string_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let bytes = line.as_bytes();
    let mut i = line.find(&needle)? + needle.len();
    while matches!(bytes.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    // The value must be a string; `null` and anything else are rejected.
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;

    let mut out: Vec<u8> = Vec::new();
    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => return String::from_utf8(out).ok(),
            b'\\' => {
                i += 1;
                match *bytes.get(i)? {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'u' => {
                        let cp = u32::from_str_radix(line.get(i + 1..i + 5)?, 16).ok()?;
                        let ch = char::from_u32(cp)?;
                        out.extend_from_slice(ch.encode_utf8(&mut [0u8; 4]).as_bytes());
                        i += 4;
                    }
                    _ => return None,
                }
            }
            // Any other byte, including UTF-8 continuation bytes, copies through.
            _ => out.push(b),
        }
        i += 1;
    }
    None
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
         entropy {original_entropy:.2} -> {packed_entropy:.2} {sbom}",
        human_bytes(original_len),
        human_bytes(packed_len),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_bin_artifact, json_string_field};

    #[test]
    fn extracts_executable_from_a_bin_artifact() {
        let line = r#"{"reason":"compiler-artifact","target":{"kind":["bin"],"name":"app"},"executable":"/w/target/debug/app","fresh":false}"#;
        assert!(line.contains("\"reason\":\"compiler-artifact\""));
        assert!(is_bin_artifact(line));
        assert_eq!(
            json_string_field(line, "executable").as_deref(),
            Some("/w/target/debug/app"),
        );
    }

    #[test]
    fn unescapes_windows_paths() {
        let line = r#"{"executable":"C:\\Users\\me\\target\\debug\\app.exe"}"#;
        assert_eq!(
            json_string_field(line, "executable").as_deref(),
            Some(r"C:\Users\me\target\debug\app.exe"),
        );
    }

    #[test]
    fn null_executable_is_rejected() {
        let line = r#"{"reason":"compiler-artifact","target":{"kind":["lib"]},"executable":null}"#;
        assert_eq!(json_string_field(line, "executable"), None);
    }

    #[test]
    fn only_bin_kinds_match() {
        assert!(is_bin_artifact(r#"{"target":{"kind":["bin"]}}"#));
        assert!(is_bin_artifact(r#"{"target":{"kind":["bin","test"]}}"#));
        assert!(!is_bin_artifact(r#"{"target":{"kind":["lib"]}}"#));
        assert!(!is_bin_artifact(r#"{"target":{"kind":["example"]}}"#));
        assert!(!is_bin_artifact(r#"{"reason":"build-script-executed"}"#));
    }

    #[test]
    fn decodes_short_and_unicode_escapes() {
        let line = r#"{"p":"a\tb\u0041\/c"}"#;
        assert_eq!(json_string_field(line, "p").as_deref(), Some("a\tbA/c"));
    }

    #[test]
    fn missing_key_returns_none() {
        assert_eq!(json_string_field(r#"{"other":"x"}"#, "executable"), None);
    }
}
