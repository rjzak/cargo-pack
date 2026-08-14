# cargo-pack

Inspired by [UPX](https://upx.github.io), `cargo-pack` is a cargo subcommand that builds your project and packs the
resulting binary into a compressed, self-extracting executable; and it and can unpack it just like UPX.

```console
$ cargo pack build --release
   Compiling my-app v0.1.0
    Finished `release` profile [optimized] target(s)
cargo pack: my-app: 8.4 MiB -> 3.1 MiB (36.9% of original)

$ ./target/release/my-app          # runs exactly like the original
...

$ cargo pack unpack ./target/release/my-app -o my-app.orig
cargo pack: restored ./target/release/my-app -> my-app.orig (8.4 MiB)
```

Unpacking a packed binary provides a file with same hash as building with `cargo build`:

```console
$ cargo build
$ shasum target/debug/hello-world
f90476a1870054adacca158b2da3704a2242c996  target/debug/hello-world
$ cargo pack build
cargo pack: hello-world: 458.1 KiB -> 1.7 MiB (381.3% of original)
$ shasum target/debug/hello-world
49d793809969992d1e1a2c83ebd317fc3a6afbfa  target/debug/hello-world
$ cargo pack unpack target/debug/hello-world
cargo pack: restored target/debug/hello-world -> hello-world (458.1 KiB)
$ shasum hello-world 
f90476a1870054adacca158b2da3704a2242c996  hello-world
```

## Install

```console
cargo install --path .
```

This installs a `cargo-pack` binary, which cargo exposes as `cargo pack`.

## Usage

| Command | What it does |
| --- | --- |
| `cargo pack build [OPTIONS] [CARGO ARGS…]` | Runs `cargo build`, then packs each produced binary in place. |
| `cargo pack unpack <FILE> [-o OUT] [--force]` | Restores a packed binary to its original bytes. |
| `cargo pack info <FILE>` | Reports whether a file is packed, its sizes, and entropy. |

Any arguments after the build options are forwarded verbatim to `cargo build`:

```console
cargo pack build --release
cargo pack build --workspace
cargo pack build -p my-app --features=feat1,feat2
```

### Compression options

```console
cargo pack build --algorithm zstd --level 90 --release   # default is zstd@90
cargo pack build --algorithm xz --release                # strongest ratio
cargo pack build --algorithm lz4 --release               # fastest
```

`--level` is a single, uniform effort dial from **`0` (fastest, least
compression)** to **`100` (smallest, most compression)**, default **`90`**. It
is mapped onto each algorithm's native range, so you never have to remember
that, say, zstd goes to 22 while xz goes to 9:

| `--algorithm` | Codec | Notes |
| --- | --- | --- |
| `zstd` *(default)* | Zstandard | Excellent ratio, very fast decompression. |
| `deflate` | DEFLATE (raw) | Ubiquitous, modest ratio. |
| `lz4` | LZ4 (Lempel–Ziv) | Weakest ratio, quickest. Ignores `--level`. |
| `xz` | XZ / LZMA2 | Strongest ratio, slowest to pack. |
| `bzip2` | bzip2 (Burrows–Wheeler) | Strong ratio, slower than zstd. |

Every algorithm can always be *decoded*, so `cargo pack unpack` and `info` work
on any packed binary regardless of how the installed `cargo-pack` was built; the
`store` restriction only limits which algorithm you can *select* when packing.

> **Ordering matters.** `cargo pack`'s own flags (`--algorithm`, `--level`) must
> come **before** the forwarded cargo arguments. Everything from the first
> cargo argument onward is passed straight through to `cargo build`.

## How it works

`cargo-pack` is **self-hosting**: the `cargo-pack` binary is *both* the CLI and
the runtime loader. Packing copies the `cargo-pack` executable and appends the
compressed original plus a small trailing footer:

```text
[ cargo-pack stub ][ original name ][ compressed payload ][ footer body ][ trailer ]
```

When a packed binary runs, it reads its own trailing metadata, decompresses the
original into a per-user cache (verified by CRC32), and `exec`s it —
transparently forwarding all arguments. Because the packer reuses its own
already-built executable as the stub, there is no separate stub crate and no
cross-compilation step. Additionally, the trailer contains a `u16` for versioning,
in case the trailer format would change.

`cargo pack build` is idempotent: re-packing an already-packed binary recovers
the original first, so you never nest a pack inside a pack.

## Current limitations & roadmap

- **Stub overhead.** Because the whole `cargo-pack` binary is used as the stub,
  packed output has a fixed floor of ~1.4 MiB. Small programs can end up
  *larger* after packing; the win shows on larger binaries. A dedicated minimal
  stub is planned.
- **Host target only.** The stub is the packer's own binary, so packing a
  cross-compiled artifact (`--target …`) for a different platform than the
  installed `cargo-pack` is not yet supported.
- **Code signing.** Like any packer (UPX included), packing rewrites the file
  and so invalidates an existing code signature. If you need a signed artifact,
  sign the *packed* binary as the final step of your build. (On Apple Silicon,
  ad-hoc-signed dev binaries still run once packed, because the appended payload
  is an overlay outside the signed segments.)
- **Planned:** optionally renaming the executable's main section (à la UPX's
  `.upx`) to for additional fun and customisability.

## Disclosures

* AI tools where used in the creation of this project but with human supervision and guidance.
* Not yet tested on Windows.

## License

MIT
