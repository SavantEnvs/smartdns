# `_quicvarint_decode`: out-of-bounds read of the first varint byte (http3 target dropped)

Reproducer: `quicvarint-oob-read.bin` (raw bytes given to `http_head_parse` on a `http_head_init(4096,
HTTP_VERSION_3_0)` head). Any 1-byte input whose first byte is a one-byte varint (e.g. `\n`) triggers it.

- **Cause:** `_quicvarint_decode` (`src/http_parse/http3_parse.c`) dereferences `buffer[0]` before it checks
  `buffer_len`. `http3_parse_head` calls it for the frame length with `data_len - offset == 0` when the frame
  type varint ends exactly at the end of the data.
- **Impact:** ASan heap-buffer-overflow READ of 1 byte on a crafted HTTP/3 HEADERS buffer.
- **Fix:** at the top of `_quicvarint_decode`, `if (buffer_len < 1) return -1;`.

**Why there is no `http3` fuzz target:** the bug is hit by a 1-byte input, so libFuzzer crashes within the
first few executions, before any coverage report, and `gate-fuzz-smoke` ("libFuzzer iterated") cannot pass.
Guarding the harness (padding the buffer, filtering short inputs) would hide the finding, so the target is
dropped until upstream applies the one-line fix. The harness was the same shape as `fuzz_http1.c` with
`HTTP_VERSION_3_0`; the `oracle.c` known-answer test still covers HTTP/3 HEADERS parsing.
