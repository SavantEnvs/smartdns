#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the known-answer oracle that mayhem/build.sh built (build-tests/oracle).
# It links the unsanitized smartdns library and asserts DNS wire encode/decode, HTTP/1.1 and HTTP/3 head
# parsing, HPACK (RFC 7541 appendix C vectors) and URI/IP helpers against fixed expected values.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

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

ORACLE=build-tests/oracle
if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — mayhem/build.sh did not produce it" >&2
  emit_ctrf smartdns-oracle 0 1
  exit 1
fi

out=$("$ORACLE" 2>&1); rc=$?
echo "$out"

line=$(printf '%s\n' "$out" | grep -E '^ORACLE_RESULT passed=[0-9]+ failed=[0-9]+$' | tail -n1)
if [ -z "$line" ]; then
  echo "oracle printed no ORACLE_RESULT line" >&2
  emit_ctrf smartdns-oracle 0 1
  exit 1
fi
passed=${line#*passed=}; passed=${passed%% *}
failed=${line#*failed=}

# a neutered or truncated oracle can't reach this many checks
if [ "$passed" -lt 90 ]; then
  echo "only $passed checks passed, expected at least 90" >&2
  failed=$(( failed + 1 ))
fi
[ "$rc" -eq 0 ] || failed=$(( failed + 1 ))

emit_ctrf smartdns-oracle "$passed" "$failed"
