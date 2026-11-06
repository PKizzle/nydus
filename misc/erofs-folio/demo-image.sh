#!/usr/bin/env bash
# Builds an EROFS image for erofs_folio_probe to walk: 40 small inline files and one 300000-byte
# file, with mkfs.erofs placing the metadata at the end, so on a kernel with the partial-folio bug
# inodes in the last page fail. Fails unless the image ends inside a page of the given size.
#
#   demo-image.sh <out> <block size> <page size>
set -euo pipefail
out=$1 block=$2 page=$3
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
mkdir "$src/d"
for i in $(seq 40); do echo "file $i" > "$src/d/f$i"; done
head -c 300000 /dev/zero > "$src/big"
mkfs.erofs -b"$block" "$out" "$src"
len=$(stat -c %s "$out")
[ $((len % page)) -ne 0 ] || { echo "$out ($len bytes) ends on a $page-byte page boundary" >&2; exit 1; }
