#!/usr/bin/env bash
#
# mayhem/build.sh — build smartdns' fuzz harnesses, their standalone reproducers and the oracle.
# Runs in the commit image as `mayhem` in /mayhem; offline and re-runnable. Upstream builds in-tree
# (src/*.o, src/libsmartdns.a — all gitignored), so each pass starts with `make clean`.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

TARGETS="dns_decode dns_update http1 http2 hpack"
LIBS="-lssl -lcrypto -lpthread -ldl -lm -lz"
INCS="-Isrc/include -Isrc/http_parse"

# 1) Oracle: the library with upstream's normal flags, plus a known-answer program (no sanitizers).
make -C src clean >/dev/null
env -u CFLAGS -u LDFLAGS make -C src -j"$MAYHEM_JOBS" libsmartdns.a CC="$CC" CFLAGS="-O2 $COVERAGE_FLAGS"
mkdir -p build-tests
$CC -O2 $COVERAGE_FLAGS $INCS mayhem/oracle.c src/libsmartdns.a $LIBS -o build-tests/oracle

# 2) Fuzz targets: the library again, instrumented. -fsanitize=fuzzer-no-link gives the library SanCov
#    edges; without it Mayhem records zero coverage for everything but the harness.
make -C src clean >/dev/null
env -u CFLAGS -u LDFLAGS make -C src -j"$MAYHEM_JOBS" libsmartdns.a CC="$CC" \
    CFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build-tests/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o build-tests/standalone_main.o

for t in $TARGETS; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $INCS "mayhem/fuzz_$t.c" \
      build-tests/lsan_off.o src/libsmartdns.a $LIBS -o "$SRC/fuzz_$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INCS "mayhem/fuzz_$t.c" build-tests/standalone_main.o \
      build-tests/lsan_off.o src/libsmartdns.a $LIBS -o "$SRC/fuzz_$t-standalone"
done
