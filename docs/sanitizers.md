# Sanitizer test runs

Two nightly-toolchain runs complement Miri (`.github/workflows/miri.yml`) over the unit tests.
Miri cannot run the snapshotter (io_uring, FFI); these runs cover the whole workspace,
`nydus-snapshotter` included, at native speed.

| Make target          | Tool                                   | Catches                                                     |
|----------------------|----------------------------------------|-------------------------------------------------------------|
| `asan-ut-nextest`    | `-Zsanitizer=address` (ASan + LSan)    | heap/stack overflows, use-after-free, double free, leaks    |
| `careful-ut-nextest` | [cargo-careful](https://github.com/RalfJung/cargo-careful) | std precondition violations (`from_raw_parts`, `copy_nonoverlapping`, unchecked arithmetic in std, ...) |

Both use the `ut-nextest` filter (`not test(integration)`) and the Linux feature set.

CI runs them in `.github/workflows/sanitizers.yml`: nightly at 01:30 UTC, on
`workflow_dispatch`, and on pull requests labelled `sanitizers`. The job is not a required
check. The nightly toolchain is pinned in the workflow's `SANITIZER_TOOLCHAIN`.

## Running locally

Linux x86_64 or aarch64 only (ASan's Rust support and the runtime paths under test are Linux).
In a container, run as root and pass `--privileged` so the tests that need loop devices or
mounts run, as they do under `sudo` in CI:

```bash
docker run --rm --privileged -v "$PWD":/work -w /work rust:1.96-bookworm bash -c '
  apt-get update -qq && apt-get install -y -qq pkg-config liblz4-dev uuid-dev cmake protobuf-compiler
  TC=nightly-2026-10-20   # keep in step with SANITIZER_TOOLCHAIN in the workflow
  rustup toolchain install $TC --profile minimal --component rust-src
  curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C /usr/local/cargo/bin
  make asan-ut-nextest SANITIZER_TOOLCHAIN=$TC
  cargo install cargo-careful --locked && make careful-ut-nextest SANITIZER_TOOLCHAIN=$TC'
```

Pass nextest arguments through `SANITIZER_NEXTEST_ARGS` to narrow a run, for example
`make asan-ut-nextest SANITIZER_NEXTEST_ARGS="-p nydus-storage --target x86_64-unknown-linux-gnu"`.

## Notes

- **Explicit `--target`.** With `-Zsanitizer=address` in `RUSTFLAGS`, cargo must be given a
  `--target` (`SANITIZER_TARGET`, default `$(uname -m)-unknown-linux-gnu`); otherwise build
  scripts and proc macros, which run on the host, are linked against the ASan runtime too.
- **Allocator.** The binaries use mimalloc as `#[global_allocator]`, which ASan cannot see into.
  The allocator is compiled out of test builds (`cfg(not(any(miri, test)))`), so every test
  runs on the system allocator that ASan intercepts.
- **C dependencies** (lz4, zstd, zlib, sqlite, mimalloc) are not instrumented. ASan reports no
  false positives for them; it simply does not check accesses made inside them.
- **Leaks.** LeakSanitizer is on (`detect_leaks=1`). Suppressed leaks are listed with a reason in
  `misc/sanitizers/lsan.supp`; override with `LSAN_OPTIONS=...` when investigating. CI installs
  `llvm-symbolizer` (`ASAN_SYMBOLIZER_PATH`); without it reports carry raw addresses and the
  suppressions, which match on function names, do not apply.

## Miri and read-only metadata

Miri does not support file-backed `mmap` or `readahead`. Bootstraps and blob-meta files are
therefore loaded through `nydus_utils::filemap::FileMapState::load`, which takes a
`nydus_api::MetadataSource`: `Mmap` (the default, used in production) maps the region, and
`Read` copies it into a 4 KiB-aligned buffer. Both run the same parser over the same bytes.
The choice is the `metadata_source` config option (`ConfigV2::metadata_source`,
`BlobCacheEntryConfigV2::metadata_source`; see [nydusd.md](nydusd.md#metadata-loading)). Tests
pick `Read` under `cfg(miri)` through a test helper in each crate (for example
`rafs::test_util::test_config`, `builder::test_config`, `storage::meta::tests::test_source`) or
by setting `metadata_source` in the configuration they build (service).
`cfg(miri)` never appears in production code. Native test runs keep Mmap, and
`test_mmap_and_read_load_the_same_filesystem` (rafs) and
`mapped_and_copied_meta_parse_identically` (storage) check that both sources give the same result.

