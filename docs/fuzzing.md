# Fuzzing

`fuzz/` holds [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets for the
parsers that read untrusted bytes: image metadata pulled from a registry, blob metadata from a
backend or a shared cache directory, and event records from the kernel.

| Target | What it parses | Entry point |
|---|---|---|
| `rafs_bootstrap` | RAFS v5/v6 bootstrap: superblocks, inode/blob/chunk tables, prefetch table, whole-tree walk | `RafsSuper::load_from_file`, `RafsIterator` |
| `erofs_metadata` | RAFS v6 (EROFS) inodes, dirent blocks, xattrs, symlinks, chunk indexes, reached by `readdir` and name lookup | `RafsInode` accessors |
| `zran_meta` | `<blob>.blob.meta`: chunk-info array, zran inflate contexts and dictionary table, then inflating each context | `BlobCompressionContextInfo::new`, `ZranDecoder::uncompress` |
| `zstd_cursor` | zstd frame-boundary tracking during conversion, and context decoding through the streaming cursor and the in-memory path | `ZstdFrameGenerator`, `ZstdStreamCursor::read`, `decompress_context` |
| `fanotify_events` | fanotify event buffers: metadata records and info records, including `FAN_EVENT_INFO_TYPE_RANGE` (Linux only) | `nydus_service::fanotify::fuzz_event_buffer` |

`zstd_cursor` also checks a property, not just absence of crashes: every chunk the converter
recorded must decode back to the bytes it read, through both decoding paths.

`fuzz/` is a cargo workspace of its own with its own `Cargo.lock`, so the nightly toolchain and
sanitizer flags never touch the main workspace. The root `[patch.crates-io]` does not
apply across workspaces, so `fuzz/Cargo.toml` repeats the entries for crates in its graph.

## Running

Needs a nightly toolchain and `cargo install cargo-fuzz`. Linux is the reference platform;
`fanotify_events` is a no-op elsewhere.

```bash
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run rafs_bootstrap corpus/rafs_bootstrap -- -max_total_time=300
```

AddressSanitizer is on by default. The RAFS and blob-meta loaders take file paths and mmap them,
so those targets write each input to a scratch file under `$TMPDIR/nydus-fuzz-<pid>/`.

From macOS, run inside a Linux container:

```bash
docker run --rm -it -v "$PWD":/work -w /work/fuzz rust:1.96-bookworm bash -c \
  'rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz --locked &&
   cargo +nightly fuzz run zstd_cursor corpus/zstd_cursor -- -max_total_time=300'
```

## Crashes

A crash is written to `fuzz/artifacts/<target>/`. Reproduce and minimize it with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
```

A panic on malformed input is a bug: per the error-handling rules in `CLAUDE.md` it becomes an
error variant, and the minimized input becomes a unit test next to the fixed parser.

## Seed corpora

`fuzz/corpus/<target>/` holds small valid inputs so the fuzzer starts past the magic-number
checks. The RAFS seeds are v6 bootstraps: `nydus-image create --type tar-rafs` of
`tests/texture/tar/all-entry-type.tar`, `--type targz-ref` of the `tests/texture/zran/` layers,
and `tests/texture/bootstrap/rafs-v6-2.2.boot`. There is no v5 seed: `nydus-image` only writes
v6, and the v5 fixture is 11 MB, so the v5 loader is reached only by mutation. The `zran_meta` seeds are `targz-ref` blob-meta files
of the `tests/texture/zran/` layers, rewritten into the target's input format (a 24-byte prefix of
header fields, then the table area). Keep seeds small: libFuzzer mutates them byte by byte, and
large seeds slow every iteration.

## CI

`.github/workflows/fuzz.yml` runs every target for 10 minutes nightly and on demand
(`workflow_dispatch`, with the run time as an input), keeps each target's corpus in the actions
cache between runs, and uploads `fuzz/artifacts/` when a run fails. Pull requests touching the
parsers or the harnesses only build the targets, so an API change cannot leave them broken until
the next nightly run.
