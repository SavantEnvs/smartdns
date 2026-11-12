# `_dns_encode_raw`: out-of-bounds read of the stored record when re-encoding a decoded packet

Reproducer: `encode-raw-oob-read.bin` (29 bytes: a DNS header with one answer, owner name = a single label
`.`, record type 0, RDLENGTH 1). Mayhem run 1 of `dns-decode` found it; the other four crashing inputs of
that run hit the same line.

- **Cause:** `_dns_encode_raw` (`src/dns.c`, the `memcpy(context->ptr, data_context.ptr, rr_len)` after
  `_dns_get_rr_head`) re-reads the record that `dns_decode` stored, takes `rr_len` from that stored header,
  and checks it only against the *output* space (`_dns_left_len(context)`), never against the bytes left in the
  stored record (`data_context`). The stored header can be misparsed: `dns_decode` accepts an owner name whose
  label contains a `.` byte and stores it as the string `.`; `_dns_encode_domain` splits that string on `.`
  and writes three zero bytes, while `_dns_get_domain_from_packet` reads the stored name back as a one-byte
  root name. Type, class, TTL and RDLENGTH are then read two bytes late, so `rr_len` comes from other bytes
  (here the TTL: 8021) and the `memcpy` runs far past the 1-byte rdata.
- **Impact:** ASan `READ of size 8021` (heap-buffer-overflow) in `dns_encode`, which the server calls for
  cached and relayed replies after `dns_decode`; information disclosure from adjacent heap memory into the
  re-encoded reply.
- **Fix:** bound the source too: `if (_dns_left_len(context) < rr_len || _dns_left_len(&data_context) < rr_len) return -1;`
  before the `memcpy`. (The name round-trip that misaligns the header is the deeper defect; rejecting labels
  that contain `.` in `_dns_get_domain_from_packet` would remove it.) With the one-line fix all five crashing
  inputs of the run are rejected cleanly.

Replay: `/mayhem/fuzz_dns_decode-standalone mayhem/dns_decode/known-findings/encode-raw-oob-read.bin`
