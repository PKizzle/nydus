# Model checking: Kani and loom

Two tools check properties that unit tests only sample:

- **[Kani](https://model-checking.github.io/kani/)** proves that a function holds an invariant
  for *every* input, by bounded model checking. It covers parsers and offset arithmetic over
  untrusted on-disk or kernel-supplied bytes, where one overlooked value is a panic or an
  out-of-bounds read.
- **[loom](https://docs.rs/loom)** runs a concurrent test under every legal thread interleaving
  (and every weak-memory reordering of loom atomics). It covers hand-written synchronization.

Both run in `.github/workflows/kani.yml`: nightly, on demand, and on pull requests that touch
the checked modules.

## What is checked

| Tool | Harness | Property |
| --- | --- | --- |
| Kani | `storage/src/meta/chunk_info_v2.rs` `validate_decides_every_record` | `validate` decides every on-disk chunk record without panicking; an accepted ZRan or batch chunk lies inside its context |
| Kani | `storage/src/meta/chunk_info_v2.rs` `packed_fields_round_trip` | the packed offset/size/flag fields of a chunk record do not overlap |
| Kani | `rafs/src/metadata/layout/v6.rs` `superblocks_decide_every_image` | RAFS v6 superblock validation never panics, and an accepted image keeps its metadata area and tables inside the bootstrap |
| Kani | `service/src/fanotify.rs` `parse_range_stays_in_bounds` | `parse_range` never reads past the event buffer, whatever the info-record lengths say |
| Kani | `service/src/fanotify.rs` `event_walk_stays_in_bounds` | `for_each_parsable_event` never walks past the buffer, whatever `event_len` says |
| loom | `storage/src/cache/state/blob_state_map.rs` `loom_racing_readers_fetch_once` | of two readers racing for a chunk, exactly one fetches it, and the other waits for that fetch |
| loom | `storage/src/cache/state/blob_state_map.rs` `loom_failed_fetch_hands_the_slot_on` | a reader whose fetch fails releases the slot, and a waiting reader wakes and fetches |

Kani harnesses live in `#[cfg(kani)] mod verification` blocks, loom tests in
`#[cfg(all(test, nydus_loom))] mod loom_tests` blocks, next to the code they check. Neither is compiled
by a normal build.

## Running Kani

Kani runs on Linux and macOS; `service/src/fanotify.rs` is Linux-only, so its harnesses need
Linux (or a Linux container).

```bash
cargo install --locked kani-verifier
cargo kani setup

cargo kani -p nydus-storage -Z stubbing
cargo kani -p nydus-rafs -Z stubbing
cargo kani -p nydus-service -Z stubbing
# One harness:
cargo kani -p nydus-storage --harness validate_decides_every_record -Z stubbing
```

A failing proof prints the failed check with its file and line. Add `--concrete-playback=print`
to get the counterexample as a unit test that reproduces it.

Harnesses over byte buffers bound the buffer length and loop count with `#[kani::unwind(N)]`;
raise both together if the parser grows a record type.

## Running loom

loom replaces `Mutex`/`Condvar` in `blob_state_map.rs` only when both `test` and `nydus_loom` are set,
so it builds through the test harness:

```bash
RUSTFLAGS="--cfg nydus_loom" cargo test -p nydus-storage --release --lib loom_
```

`--release` matters: loom explores thousands of executions per test. A failure prints the
interleaving that broke the assertion; `LOOM_LOG=trace LOOM_LOCATION=1` adds a step-by-step
trace. loom's `Condvar::wait_timeout` never times out, so a lost wakeup fails as a deadlock
instead of hiding behind the production wait timeout.

Only the `loom_` tests are meaningful under `--cfg nydus_loom`: every other test in the crate that
touches `BlobStateMap` would use loom primitives outside `loom::model` and panic.
