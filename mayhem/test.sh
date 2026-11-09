#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for the libraries asuswrt-merlin.ng bundles (zlib, expat, dnsmasq,
# openssl-1.1), run against the normal-flag binaries mayhem/build.sh left in mayhem/build/oracle.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


O="$SRC/mayhem/build/oracle"
CERTS="$SRC/release/src/router/openssl-1.1/test/certs"
for f in zlib-example zlib-kat expat-kat dnsmasq-kat openssl; do
  [ -x "$O/$f" ] || { echo "missing $O/$f: mayhem/build.sh did not build it" >&2; exit 2; }
done
[ -f "$CERTS/ca-cert.pem" ] || { echo "missing $CERTS/ca-cert.pem" >&2; exit 2; }

pass=0; fail=0
# expect <name> <expected line> <actual output>: the expected line must be present, verbatim
expect() {
  if printf '%s\n' "$3" | grep -qxF -- "$2"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $1: wanted '$2'" >&2; fi
}

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

# zlib: upstream's own example.c (it writes foo.gz in cwd), then known answers
out=$("$O/zlib-example" 2>&1); rc=$?
[ "$rc" -eq 0 ] && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL zlib-example rc=$rc" >&2; }
for l in "uncompress(): hello, hello!" "gzread(): hello, hello!" "gzgets() after gzseek:  hello!" \
         "inflate(): hello, hello!" "large_inflate(): OK" "after inflateSync(): hello, hello!" \
         "inflate with dictionary: hello, hello!"; do
  expect zlib-example "$l" "$out"
done
out=$("$O/zlib-kat" 2>&1)
for l in "adler32(Wikipedia)=11e60398" "crc32(123456789)=cbf43926" "compressed_smaller=1" \
         "roundtrip_len=68 equal=1" "known_stream=hello"; do
  expect zlib-kat "$l" "$out"
done

# expat: element tree, character count, and the well-formedness error text
out=$("$O/expat-kat" 2>&1)
for l in '<root id="7">' '  <a k="v">' "elements=4 chars=15" "mismatch=mismatched tag line=1"; do
  expect expat-kat "$l" "$out"
done

# dnsmasq: a reply is cached by extract_addresses(); a query is answered from --host-record
out=$("$O/dnsmasq-kat" 2>&1)
for l in "cached kat.example A=203.0.113.7" "answer len=50 ancount=1 rcode=0 hb3=85" "answer last A=192.0.2.5"; do
  expect dnsmasq-kat "$l" "$out"
done

# openssl 1.1.1w: stock CLI
out=$("$O/openssl" version 2>&1)
expect openssl-version "OpenSSL 1.1.1w  11 Sep 2023" "$out"
out=$(printf abc | "$O/openssl" dgst -sha256 2>&1)
expect openssl-sha256 "(stdin)= ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" "$out"
out=$(printf abc | "$O/openssl" dgst -md5 2>&1)
expect openssl-md5 "(stdin)= 900150983cd24fb0d6963f7d28e17f72" "$out"
out=$("$O/openssl" x509 -in "$CERTS/ca-cert.pem" -noout -subject -issuer -serial 2>&1)
expect openssl-x509-subject "subject=CN = CA" "$out"
expect openssl-x509-issuer "issuer=CN = Root CA" "$out"
expect openssl-x509-serial "serial=02" "$out"
out=$("$O/openssl" asn1parse -in "$CERTS/ca-cert.pem" 2>&1)
expect openssl-asn1parse "    0:d=0  hl=4 l= 748 cons: SEQUENCE          " "$out"
out=$("$O/openssl" verify -CAfile "$CERTS/root-cert.pem" "$CERTS/ca-cert.pem" 2>&1)
expect openssl-verify "$CERTS/ca-cert.pem: OK" "$out"

cd "$SRC"
emit_ctrf "asuswrt-merlin.ng known-answer oracle" "$pass" "$fail"
