#!/usr/bin/env bash
#
# mayhem/build.sh — builds the fuzz harnesses (sanitized) and the oracle binaries (normal flags) for
# the third-party libraries asuswrt-merlin.ng carries under release/src/router: zlib, expat-2.1.0
# and openssl-1.1 (1.1.1w). Everything is built out of tree under mayhem/build (gitignored), so the
# build is re-runnable and needs no network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"
ROUTER=$SRC/release/src/router
ZLIB=$ROUTER/zlib
EXPAT=$ROUTER/expat/expat-2.1.0
OSSL=$ROUTER/openssl-1.1
H=$SRC/mayhem/harnesses
B=$SRC/mayhem/build
mkdir -p "$B"

# SanCov on the library objects, unconditionally (also when SANITIZER_FLAGS is empty)
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1"

# ---- shared objects: standalone driver (C), LSan off hook ----
mkdir -p "$B/common"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$B/common/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/common/lsan_off.o"

# link_pair <name> <libs...> -- <objects...>
# links $B/obj/<name>.o-style objects into the fuzzer and its -standalone reproducer
link_pair() {
  local name=$1; shift
  local libs=() objs=()
  while [ "$1" != "--" ]; do libs+=("$1"); shift; done; shift
  objs=("$@")
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${objs[@]}" "$B/common/lsan_off.o" "${libs[@]}" -o "$SRC/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${objs[@]}" "$B/common/standalone_main.o" "$B/common/lsan_off.o" "${libs[@]}" -o "$SRC/$name-standalone"
}

# ======================= zlib =======================
mkdir -p "$B/zlib"
ZSRCS="adler32 compress crc32 deflate gzclose gzlib gzread gzwrite infback inffast inflate inftrees trees uncompr zutil"
zobjs=()
for s in $ZSRCS; do
  $CC $FUZZ_CFLAGS -D_LARGEFILE64_SOURCE=1 -I"$ZLIB" -c "$ZLIB/$s.c" -o "$B/zlib/$s.o"
  zobjs+=("$B/zlib/$s.o")
done
rm -f "$B/zlib/libz.a"; ar rcs "$B/zlib/libz.a" "${zobjs[@]}"
for t in inflate roundtrip; do
  $CC $FUZZ_CFLAGS -I"$ZLIB" -c "$H/fuzz_zlib_$t.c" -o "$B/zlib/fuzz_zlib_$t.o"
  link_pair "fuzz_zlib_$t" "$B/zlib/libz.a" -- "$B/zlib/fuzz_zlib_$t.o"
done

# ======================= expat 2.1.0 =======================
mkdir -p "$B/expat"
eobjs=()
for s in xmlparse xmlrole xmltok; do
  $CC $FUZZ_CFLAGS -fno-sanitize=pointer-overflow,shift-base -DXML_NS=1 -DXML_DTD=1 -DXML_CONTEXT_BYTES=1024 -DHAVE_MEMMOVE=1 \
      -I"$EXPAT/lib" -c "$EXPAT/lib/$s.c" -o "$B/expat/$s.o"
  eobjs+=("$B/expat/$s.o")
done
rm -f "$B/expat/libexpat.a"; ar rcs "$B/expat/libexpat.a" "${eobjs[@]}"
$CC $FUZZ_CFLAGS -I"$EXPAT/lib" -c "$H/fuzz_expat_parse.c" -o "$B/expat/fuzz_expat_parse.o"
link_pair fuzz_expat_parse "$B/expat/libexpat.a" -- "$B/expat/fuzz_expat_parse.o"

# ======================= openssl 1.1.1w =======================
# Out-of-tree configure (the source dir has no Makefile). Mirrors OSS-Fuzz's openssl configuration
# minus enable-fuzz-libfuzzer, whose driver we replace with mayhem/harnesses/openssl_driver.c.
OSSL_OPTS="no-shared no-asm no-tests no-dso no-afalgeng enable-tls1_3 enable-rc5 enable-md2
           enable-ssl3 enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers enable-ec_nistp_64_gcc_128"
mkdir -p "$B/openssl-fuzz"
(
  cd "$B/openssl-fuzz"
  perl "$OSSL/Configure" linux-x86_64-clang $OSSL_OPTS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
       $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -fno-sanitize=alignment,function -O1 >/dev/null
  make -j"$MAYHEM_JOBS" build_generated >/dev/null
  make -j"$MAYHEM_JOBS" libcrypto.a libssl.a >/dev/null
)
OF=$B/openssl-fuzz
$CC $FUZZ_CFLAGS -I"$OF/include" -I"$OSSL/include" -c "$H/openssl_driver.c" -o "$OF/openssl_driver.o"
for t in asn1 asn1parse bignum bndiv client cms conf crl ct server x509; do
  $CC $FUZZ_CFLAGS -fno-sanitize=alignment,function -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
      -I"$OF/include" -I"$OSSL/include" -I"$OSSL" -I"$OSSL/fuzz" \
      -c "$OSSL/fuzz/$t.c" -o "$OF/fuzz_$t.o"
  link_pair "fuzz_openssl_$t" "$OF/libssl.a" "$OF/libcrypto.a" -ldl -pthread -- "$OF/fuzz_$t.o" "$OF/openssl_driver.o"
done


# ======================= dnsmasq 2.93 =======================
# Every dnsmasq source file is built as a library (main() renamed), so harnesses reach the real
# option parser, cache and DNS packet code.
DNSMASQ=$ROUTER/dnsmasq
DNSMASQ_SRCS="arp auth blockdata cache conntrack crypto dbus dhcp6 dhcp dhcp-common dnsmasq domain domain-match dump edns0 forward helper inotify ipset lease log loop metrics netlink network nftset option outpacket pattern poll radv rfc1035 rfc2131 rfc3315 rrfilter slaac tables tftp ubus util"
DNSMASQ_DEFS="-DVERSION=\"2.93\" -Dmain=dnsmasq_main"
mkdir -p "$B/dnsmasq"
dobjs=()
for s in $DNSMASQ_SRCS; do
  $CC $FUZZ_CFLAGS -fno-sanitize=alignment,pointer-overflow $DNSMASQ_DEFS -I"$DNSMASQ/src" -c "$DNSMASQ/src/$s.c" -o "$B/dnsmasq/$s.o"
  dobjs+=("$B/dnsmasq/$s.o")
done
rm -f "$B/dnsmasq/libdnsmasq.a"; ar rcs "$B/dnsmasq/libdnsmasq.a" "${dobjs[@]}"
for t in reply request; do
  $CC $FUZZ_CFLAGS -I"$DNSMASQ/src" -c "$H/fuzz_dnsmasq_$t.c" -o "$B/dnsmasq/fuzz_dnsmasq_$t.o"
  link_pair "fuzz_dnsmasq_$t" "$B/dnsmasq/libdnsmasq.a" -- "$B/dnsmasq/fuzz_dnsmasq_$t.o"
done

# ======================= oracle (normal flags, no sanitizers) =======================
O=$B/oracle
mkdir -p "$O"
# zlib: upstream's example.c (asserts every API path) plus a known-answer probe
$CC -O2 $COVERAGE_FLAGS -D_LARGEFILE64_SOURCE=1 -I"$ZLIB" \
    $(for s in $ZSRCS; do echo "$ZLIB/$s.c"; done) "$ZLIB/test/example.c" -o "$O/zlib-example"
$CC -O2 $COVERAGE_FLAGS -D_LARGEFILE64_SOURCE=1 -I"$ZLIB" \
    $(for s in $ZSRCS; do echo "$ZLIB/$s.c"; done) "$SRC/mayhem/kat/zlib_kat.c" -o "$O/zlib-kat"
# expat
$CC -O2 $COVERAGE_FLAGS -DXML_NS=1 -DXML_DTD=1 -DXML_CONTEXT_BYTES=1024 -DHAVE_MEMMOVE=1 -I"$EXPAT/lib" \
    "$EXPAT/lib/xmlparse.c" "$EXPAT/lib/xmlrole.c" "$EXPAT/lib/xmltok.c" "$SRC/mayhem/kat/expat_kat.c" -o "$O/expat-kat"
# dnsmasq: normal-flag objects, a probe that parses a reply and answers a query
mkdir -p "$O/dnsmasq"
for s in $DNSMASQ_SRCS; do
  $CC -O2 $COVERAGE_FLAGS $DNSMASQ_DEFS -I"$DNSMASQ/src" -c "$DNSMASQ/src/$s.c" -o "$O/dnsmasq/$s.o"
done
$CC -O2 $COVERAGE_FLAGS -I"$DNSMASQ/src" "$SRC/mayhem/kat/dnsmasq_kat.c" "$O"/dnsmasq/*.o -o "$O/dnsmasq-kat"
# openssl: the stock command-line tool, default flags
mkdir -p "$B/openssl-normal"
(
  cd "$B/openssl-normal"
  env -u CFLAGS -u LDFLAGS perl "$OSSL/Configure" linux-x86_64-clang no-shared no-tests no-dso no-afalgeng $COVERAGE_FLAGS >/dev/null
  make -j"$MAYHEM_JOBS" build_generated >/dev/null
  make -j"$MAYHEM_JOBS" apps/openssl >/dev/null
)
cp "$B/openssl-normal/apps/openssl" "$O/openssl"
echo "build.sh: done"
