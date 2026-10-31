# Node-local acceleration of zstd and uncompressed layers

**Date:** 2026-10-31
**Status:** Approved

## Goal

Node-local acceleration handles every standard OCI layer encoding, not only gzip, without
writing a second copy of the layer data:

| Layer | Route | Extra disk |
|---|---|---|
| `tar+gzip` | zran reference (existing) | zran index |
| `tar` (uncompressed) | tar reference: chunks point into the layer as is (existing `TarToRef`) | chunk table |
| `tar+zstd` | zstd reference: contexts that start at frame boundaries | chunk + context table |

One image may mix all three. Each layer picks its route from its media type.

## Background

- zran gives random access into gzip because a deflate stream can be resumed at a block
  boundary from a 32 KiB window. A zstd frame can only be resumed from its start: inside a
  frame the decoder needs up to the full window (8 MiB in Home Assistant's layers) plus
  entropy state, which libzstd cannot save. No container project indexes inside a frame:
  SOCI declined it (awslabs/soci-snapshotter#519), and stargz, overlaybd TurboOCI and
  containers/storage fall back to a full unpack. nydus zran is gzip-only
  (dragonflyoss/nydus#1562).
- Frame boundaries are free resume points. zstd:chunked (containers/storage) writes each file's
  content as separate frames; the zstd seekable format writes fixed-size frames. Concatenated
  frames decode as one stream, so a range starting at a frame start is a self-contained decode
  unit.
- Most zstd layers in practice are one frame (Home Assistant: 22 of 22). Decode throughput,
  single-threaded, measured with Home Assistant's largest layer (376 MiB compressed,
  1394 MiB decompressed): 330 MiB/s on raspberrypi-5-1 (4.2 s for the whole layer) and
  100–130 MiB/s on raspberrypi-4-1 (10.5–13.8 s).

## Design

### 1. zstd contexts (utils, storage meta, builder)

The zran on-disk structures already describe "decode compressed bytes `[in_offset, +in_len)`
into output `[out_offset, +out_len)`, primed with `dict`". A zstd context is the same record
with an empty dictionary whose `in_offset` is a frame start.

- **utils `compress::zstd_frames`:** `ZstdFrameReader` (counterpart of `ZranReader`) decodes with
  libzstd's streaming API, hashes and counts the input, and records the input and output
  position of the current frame start. `ZstdFrameGenerator` (counterpart of `ZranGenerator`)
  assigns each chunk to the context that starts at the frame start at or before the chunk,
  creating a new context when the chunk begins in a later frame and extending the context to
  the chunk's end otherwise.
- **Limit:** a chunk's offset inside its context is a `u32`, so a frame may decode to at most
  4 GiB. A larger frame fails the conversion, and the image stays on plain overlay.
- **Blob format:** the blob keeps `BlobFeatures::ZRAN` (same chunk table, same context table)
  and records `compressor = zstd`; gzip zran blobs keep `compressor = gzip`. No new feature bit,
  no on-disk layout change.
- **builder:** `detect_compression_algo` recognises the zstd frame magic (`28 b5 2f fd`) and the
  skippable-frame magics (`5? 2a 4d 18`). A ref conversion (`targz-ref`) of a zstd layer uses
  the frame generator and sets the blob compressor to zstd after sniffing; an uncompressed
  layer keeps the existing `TarToRef` path.

### 2. Serving zstd contexts (storage)

- **Small contexts** (decoded size ≤ `RAFS_MAX_CHUNK_SIZE`, 16 MiB: multi-frame layers and small
  layers) take the zran path: the backend range is read once and decoded in memory, with libzstd
  instead of the inflate decoder, chosen by the blob's compressor.
- **Large contexts** (single-frame layers) are never read into memory as a whole. Each blob
  keeps one forward-running decoder cursor (context, compressed position, decoded position,
  libzstd state). A read at or ahead of the cursor decodes forward to it, reading the backend
  in 1 MiB pieces; a read behind it restarts the cursor at the context start. Only the
  requested chunks are returned and cached, exactly as for zran. Reads of one blob through the
  cursor are serialized.
- Worst case: the first read near the end of a large single-frame layer decodes the layer once
  (about 4 s on a Pi 5, 11–14 s on a Pi 4 for Home Assistant's largest layer). The existing
  optimize stage packs the startup working set into the prefetch blob after the first run, so
  later starts do not reach the cursor for startup reads.

### 3. Layer selection (snapshotter)

- `gzip_layers_from_manifest` becomes `accel_layers_from_manifest` and accepts `tar`,
  `tar+gzip` and `tar+zstd` (OCI and Docker media types). `GzipLayer` becomes `SourceLayer`.
  Other encodings keep the up-front rejection.
- All three go through the same per-layer `targz-ref` conversion and merge. The sidecar format
  does not change: each layer is still referenced by its original digest plus an optional index
  blob.

### Out of scope

- Indexing inside a zstd frame (checkpointing decoder state): rejected, see Background.
- Writing a converted copy of a layer: rejected in favour of decoding on demand, which needs no
  extra disk beyond the cache.
- Recompressing the original image or pushing anything to a registry.

## Testing

- **utils unit tests:** frame-start tracking over multi-frame input with skippable frames,
  contexts per chunk (new context per frame, extension within a frame), digest and size of the
  consumed input.
- **storage unit tests:** in-memory zstd context decode; the cursor reading forward, re-reading
  behind its position, and switching contexts.
- **builder tests:** multi-frame and single-frame zstd tars and an uncompressed tar converted
  with `targz-ref`, checked with `nydus-image check`, with zstd blobs recording
  `compressor = zstd`.
- **fanotify integration** (`misc/fanotify/zran-multilayer-test.sh` extended): one image mixing
  gzip, uncompressed, multi-frame zstd and single-frame zstd layers is converted, merged,
  mounted through fanotify/EROFS and compared file by file with the unpacked tars.
- **snapshotter unit tests:** media-type selection.
- **Cluster:** on raspberrypi-5-1, Home Assistant converts and starts from the accelerated mount.
