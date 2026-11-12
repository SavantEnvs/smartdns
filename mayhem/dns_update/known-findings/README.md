# `_dns_update_domain`: out-of-bounds read of the caller's domain string

Reproducer: `update-domain-oob-read.bin` (first byte selects the harness `query_domain`, here `example.com`;
the rest is the packet handed to `dns_packet_update`).

- **Cause:** `_dns_update_domain` (`src/dns.c`, the `memcpy(ptr, domain + processed_len, len)` after
  `/* update domain */`) takes `len` from each label length byte in the *packet* and copies that many bytes
  from the caller-supplied `domain` string. The loop only checks `processed_len > domain_len + 1` before the
  label is read, never `processed_len + len <= domain_len`, so a label longer than the remaining domain
  reads past the end of `domain`. The destination is not bounded by the packet end either.
- **Impact:** ASan `READ of size 6` (global-buffer-overflow) on a crafted DNS packet; information disclosure
  and a possible write past the packet buffer. Reached via `dns_packet_update` on a packet parsed from an
  upstream or client reply.
- **Fix:** before the `memcpy`, `if (processed_len + len > domain_len || ptr + 1 + len > packet + packet_size) return -1;`.

Replay: `/mayhem/fuzz_dns_update-standalone mayhem/dns_update/known-findings/update-domain-oob-read.bin`
