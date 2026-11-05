#!/usr/bin/env bash
# Checks the output of `erofs_folio_probe <dir> [<image>]` against the verdict expected for the
# kernel it ran on, and fails loudly otherwise. With an image walked as well: the padded copy must
# read cleanly on every kernel, and the unpadded one must fail on an affected kernel (the image
# reproduces the bug) and read cleanly on an unaffected one.
#
#   expect.sh <probe output> [affected|unaffected]   (no expectation: only print the verdict)
set -u
log=$1 expect=${2:-}
status=$(sed -n 's/.*erofs-folio-probe: .* status=\([a-z]*\).*/\1/p' "$log" | tr -d '\r')
echo "==== EROFS FOLIO PROBE: ${status:-none} ===="
[ -n "$expect" ] || exit 0
fail() { echo "::error::erofs-folio: $*"; exit 1; }
[ "$status" = "$expect" ] || fail "probe says '${status:-none}', expected '$expect'"
grep -q '/unpadded\.erofs: ' "$log" || exit 0
grep -q '/padded\.erofs: .*, 0 failed' "$log" || fail "the padded image did not read cleanly"
unpadded_clean=$(grep -c '/unpadded\.erofs: .*, 0 failed' "$log")
case "$expect:$unpadded_clean" in
  affected:0 | unaffected:1) ;;
  affected:*) fail "the unpadded image read cleanly, so it does not reproduce the bug" ;;
  *) fail "the unpadded image failed on a kernel the probe calls unaffected" ;;
esac
echo "==== EROFS FOLIO IMAGE: padded reads cleanly, unpadded as expected ===="
