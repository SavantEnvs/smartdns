/* Rewrites a received DNS packet in place the way the server does before replying from cache
 * (dns_packet_update: new id, new TTLs, query-name case restored), then decodes the result. The first
 * input byte picks which query name to restore. */
#include "smartdns/dns.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *const names[] = {"example.com", "a.b", "www.example.org", "x", "mixed.Case.Example.COM"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 13 || size > DNS_IN_PACKSIZE) {
		return -1;
	}

	const char *query_domain = names[data[0] % (sizeof(names) / sizeof(names[0]))];
	data++;
	size--;

	unsigned char *buf = malloc(size);
	struct dns_packet *packet = malloc(DNS_PACKSIZE);
	if (!buf || !packet) {
		abort();
	}
	memcpy(buf, data, size);

	struct dns_update_param param = {.id = 0x1234, .ip_ttl = 60, .cname_ttl = 30, .query_domain = query_domain};
	int ret = dns_packet_update(buf, (int)size, &param);
	if (ret == 0) {
		dns_decode(packet, DNS_PACKSIZE, buf, (int)size);
	}

	free(buf);
	free(packet);
	return ret == 0 ? 0 : -1;
}
