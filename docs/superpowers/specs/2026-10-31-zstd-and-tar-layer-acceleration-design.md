# Node-local acceleration of zstd and uncompressed layers

**Date:** 2026-10-31
**Status:** Draft

## Goal

Node-local acceleration handles every standard OCI layer encoding, not only gzip:

| Layer | Route | Extra disk |
|---|---|---|
| `tar+gzip` | zran reference (existing) | zran index |
| `tar` (uncompressed) | tar reference: chunks point into the layer as is | chunk table only |
| `tar+zstd`, every frame ≤ 16 MiB decompressed (zstd:chunked, seekable format, small layers) | zstd-frame reference: zran-style contexts that start at frame boundaries | context table only |
| `tar+zstd` with a larger frame (single-frame streams, e.g. Home Assistant) | convert: decompress once into a native RAFS data blob | about the compressed layer size |

One image may mix all four. Each layer picks its route independently.

## Background

- zran gives random access into gzip because a deflate stream can be resumed at a block
  boundary from a 32 KiB window. A zstd frame can only be resumed from its start; inside a
  frame the decoder needs up to the full window (8 MiB in Home Assistant's layers) plus
  entropy state, which libzstd cannot save. No container project indexes inside a frame:
  SOCI declined it (awslabs/soci-snapshotter#519), and stargz, overlaybd TurboOCI and
  containers/storage fall back to a full unpack. nydus zran is gzip-only
  (dragonflyoss/nydus#1562).
- Frame boundaries are free resume points. zstd:chunked (containers/storage) writes each file's
  content as separate frames; the zstd seekable format writes fixed-size frames. Concatenated
  frames decode as one stream, so a range of frames is a self-contained decode unit.

## Design

### 1. zstd-frame contexts (builder, utils, storage)

The zran on-disk structures already describe "decode compressed bytes `[in_offset, +in_len)`
into output `[out_offset, +out_len)`, priming the decoder with `dict`". A zstd context is the
same record with an empty dictionary whose `in_offset` is a frame start.

- **utils:** `compress::zstd_frames` with `ZstdFrameReader` and `ZstdFrameGenerator`, the
  counterparts of `ZranReader`/`ZranGenerator`. The reader decodes with libzstd's streaming
  API and records the input and output position of every frame start (skippable frames
  produce no output and are skipped). `begin_read`/`end_read` assign each chunk to a context
  starting at the last frame start at or before the chunk, extending it like zran does.
- **Bound:** a context never exceeds `RAFS_MAX_CHUNK_SIZE` (16 MiB) of output, the storage
  layer's decode-buffer limit. A chunk that would need more fails the build with a typed
  `FrameTooLarge` error, which `nydus-image` reports with a dedicated exit code.
- **Blob format:** the blob keeps `BlobFeatures::ZRAN` (same chunk table, same context table)
  and records `compressor = zstd`; gzip zran blobs keep `compressor = gzip`. No new feature bit
  and no on-disk layout change.
- **storage:** `decompress_zran` branches on the blob's compressor. zstd decodes the context's
  input range with libzstd into `out_len` bytes and checks that exactly `out_len` came out.
- **builder:** `detect_compression_algo` recognises the zstd magic (`28 b5 2f fd`) and the
  skippable-frame magics. For `targz-ref` a zstd layer
  uses the frame generator; an uncompressed layer uses the existing `TarToRef` path.

### 2. Convert route (builder, snapshotter)

- **builder:** `tar-rafs` accepts a zstd-compressed tar and decompresses it while reading, so no
  temporary tar is written.
- **snapshotter `local_accel`:** per layer, run the reference conversion first. On the
  `FrameTooLarge` exit code, run `nydus-image create --type tar-rafs` on the same layer blob
  instead. The output is a native data blob (chunks compressed with nydus's default zstd)
  with a content digest of its own.
- The converted blob is a real file in the backend directory; its blob id is its digest, and
  `merge --original-blob-ids` receives that id for the layer.

### 3. Layer selection and sidecar (snapshotter)

- `gzip_layers_from_manifest` becomes `accel_layers_from_manifest` and accepts `tar`, `tar+gzip`
  and `tar+zstd` (OCI and Docker media types). `GzipLayer` becomes `SourceLayer` with the media
  type. Other encodings keep the up-front rejection.
- `NodeLocalArtifact` records per layer which route it took: reference (data = the original
  layer, plus an optional index blob) or converted (data = the new blob).
- The sidecar manifest carries a converted layer's data blob as its own descriptor, so peers
  fetch it instead of reading their own copy of the original layer. This changes the wire
  format: `AUTO_ACCEL_MANIFEST_VERSION` becomes 3, and older sidecars read as `Stale` and are
  rebuilt (PR #24 path).
- GC: converted blobs are referenced from the sidecar manifest (`gc.ref.content.*`) like index
  blobs, so they live exactly as long as the sidecar.

### Out of scope

- Indexing inside a zstd frame (checkpointing decoder state): rejected, see Background.
- Converting layers that are already referenced cheaply.
- Recompressing the original image or pushing anything to a registry.

## Testing

- **utils/storage unit tests:** frame boundaries and contexts for multi-frame input, skippable
  frames, a frame over the bound → `FrameTooLarge`, and zstd context decode round trips.
- **builder tests:** a zstd:chunked-style multi-frame tar converted with `targz-ref` and checked
  with `nydus-image check`; an uncompressed tar the same way; a single-frame large zstd tar
  failing with the dedicated exit code; `tar-rafs` from a zstd tar.
- **fanotify integration** (`misc/fanotify/zran-multilayer-test.sh` extended): one image mixing
  gzip, uncompressed, multi-frame zstd and single-frame zstd layers is converted, merged,
  mounted through fanotify/EROFS and compared file by file with the unpacked tars.
- **snapshotter unit tests:** route selection per media type, the fallback on `FrameTooLarge`,
  manifest v3 descriptors for converted blobs.
- **Cluster:** on raspberrypi-5-1, Home Assistant (22 single-frame zstd layers) converts and
  starts from the accelerated mount.
