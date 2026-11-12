/* Decodes a DNS wire packet with smartdns' own decoder, as the server (query path), client (reply path)
 * and cache (stored reply) all do, then reads every record through the public getters and
 * re-encodes the packet. */
#include "smartdns/dns.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void walk_records(struct dns_packet *packet)
{
	char name[DNS_MAX_CNAME_LEN];
	char target[DNS_MAX_CNAME_LEN];
	int ttl = 0;
	int count = 0;
	int i;
	int sect;

	for (sect = DNS_RRS_QD; sect <= DNS_RRS_NR; sect++) {
		struct dns_rrs *rrs = dns_get_rrs_start(packet, sect, &count);
		for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			name[0] = '\0';
			if (sect == DNS_RRS_QD) {
				int qtype = 0, qclass = 0;
				dns_get_domain(rrs, name, sizeof(name), &qtype, &qclass);
				continue;
			}

			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[DNS_RR_A_LEN];
				dns_get_A(rrs, name, sizeof(name), &ttl, addr);
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[DNS_RR_AAAA_LEN];
				dns_get_AAAA(rrs, name, sizeof(name), &ttl, addr);
			} break;
			case DNS_T_CNAME:
				dns_get_CNAME(rrs, name, sizeof(name), &ttl, target, sizeof(target));
				break;
			case DNS_T_NS:
				dns_get_NS(rrs, name, sizeof(name), &ttl, target, sizeof(target));
				break;
			case DNS_T_PTR:
				dns_get_PTR(rrs, name, sizeof(name), &ttl, target, sizeof(target));
				break;
			case DNS_T_TXT:
				dns_get_TXT(rrs, name, sizeof(name), &ttl, target, sizeof(target));
				break;
			case DNS_T_SOA: {
				struct dns_soa soa;
				dns_get_SOA(rrs, name, sizeof(name), &ttl, &soa);
			} break;
			case DNS_T_SRV: {
				unsigned short priority, weight, port;
				dns_get_SRV(rrs, name, sizeof(name), &ttl, &priority, &weight, &port, target, sizeof(target));
			} break;
			case DNS_T_SVCB:
			case DNS_T_HTTPS: {
				struct dns_svcparam *p = NULL;
				int priority = 0;
				volatile unsigned char sink = 0;
				if (dns_svcparm_start(rrs, &p, name, sizeof(name), &ttl, &priority, target, sizeof(target)) != 0) {
					break;
				}
				for (; p; p = dns_svcparm_next(rrs, p)) {
					int k;
					for (k = 0; k < p->len; k++) {
						sink ^= p->value[k];
					}
				}
			} break;
			default:
				break;
			}
		}
	}

	count = 0;
	struct dns_rrs *rrs = dns_get_rrs_start(packet, DNS_RRS_OPT, &count);
	for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		if (rrs->type == DNS_OPT_T_ECS) {
			struct dns_opt_ecs ecs;
			memset(&ecs, 0, sizeof(ecs));
			dns_get_OPT_ECS(rrs, &ecs);
		} else if (rrs->type == DNS_OPT_T_TCP_KEEPALIVE) {
			unsigned short timeout = 0;
			dns_get_OPT_TCP_KEEPALIVE(rrs, &timeout);
		}
	}
	dns_get_OPT_payload_size(packet);
	dns_get_OPT_option(packet);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 12 || size > DNS_PACKSIZE) {
		return -1;
	}

	unsigned char *in = malloc(size);
	struct dns_packet *packet = malloc(DNS_PACKSIZE);
	unsigned char *out = malloc(DNS_PACKSIZE);
	if (!in || !packet || !out) {
		abort();
	}
	memcpy(in, data, size);

	int ret = dns_decode(packet, DNS_PACKSIZE, in, (int)size);
	if (ret == 0) {
		walk_records(packet);
		dns_encode(out, DNS_PACKSIZE, packet);
	}

	free(in);
	free(packet);
	free(out);
	return ret == 0 ? 0 : -1;
}
