// SPDX-License-Identifier: MIT

//! Build script.
//!
//! On macOS, reserve a fixed-size, neutrally-named section in the `cargo-pack`
//! binary via the linker (`ld64 -sectcreate`). At pack time `cargo pack` copies
//! a cargo-auditable SBOM into this slot and renames it to `.dep-v0` in place,
//! which keeps the packed Mach-O auditable without fragile object surgery. See
//! `src/auditable.rs`. Doing this through the linker avoids a `#[link_section]`
//! attribute, which would require `unsafe` (forbidden crate-wide).

use std::io::Result;

/// Must match `auditable::SLOT_LEN`.
const SLOT_LEN: usize = 64 * 1024;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    let macos = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos");
    let slot_enabled = std::env::var_os("CARGO_FEATURE_MACOS_AUDITABLE").is_some();
    if macos && slot_enabled {
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is set for build scripts");
        let filler = std::path::Path::new(&out_dir).join("cgpk_sbom_slot.bin");
        std::fs::write(&filler, vec![0x5A_u8; SLOT_LEN])?;

        // ld64: `-sectcreate <segment> <section> <file>` — creates __DATA,__cgpkslot
        // from the filler. Passed through the clang driver with `-Wl,`.
        println!(
            "cargo:rustc-link-arg-bins=-Wl,-sectcreate,__DATA,__cgpkslot,{}",
            filler.display()
        );
    }

    Ok(())
}
