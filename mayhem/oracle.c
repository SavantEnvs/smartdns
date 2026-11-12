/* Known-answer oracle for smartdns' wire-format code. Built against the normal (unsanitized) library by
 * mayhem/build.sh and run by mayhem/test.sh. Every check compares a computed value against a value fixed
 * by the DNS / HTTP / HPACK specifications. */
#include "hpack.h"
#include "smartdns/dns.h"
#include "smartdns/http_parse.h"
#include "smartdns/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass;
static int g_fail;

#define CHECK(name, cond)                                                                                              \
	do {                                                                                                               \
		if (cond) {                                                                                                    \
			g_pass++;                                                                                                  \
		} else {                                                                                                       \
			g_fail++;                                                                                                  \
			printf("FAIL %s (%s:%d)\n", name, __FILE__, __LINE__);                                                     \
		}                                                                                                              \
	} while (0)

/* RFC 1035: id 0x1234, QR RD RA, 1 question, 1 answer; the answer name is a compression pointer to offset 12 */
static const unsigned char dns_a_response[] = {
	0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,
	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 93,   184,  216,  34};

/* CNAME www.example.com -> example.com, then AAAA 2001:db8::1 */
static const unsigned char dns_cname_aaaa[] = {
	0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',  0x00,
	0x00, 0x1c, 0x00, 0x01,
	0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x10,
	0xc0, 0x10, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10,
	0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};

static void test_dns_encode(void)
{
	unsigned char buf[DNS_PACKSIZE];
	unsigned char out[DNS_IN_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)buf;
	struct dns_head head;
	unsigned char addr[DNS_RR_A_LEN] = {93, 184, 216, 34};

	memset(&head, 0, sizeof(head));
	head.id = 0x1234;
	head.qr = DNS_QR_ANSWER;
	head.opcode = DNS_OP_QUERY;
	head.rd = 1;
	head.ra = 1;

	CHECK("packet_init", dns_packet_init(packet, sizeof(buf), &head) == 0);
	CHECK("add_domain", dns_add_domain(packet, "example.com", DNS_T_A, DNS_C_IN) == 0);
	CHECK("add_A", dns_add_A(packet, DNS_RRS_AN, "example.com", 300, addr) == 0);
	int len = dns_encode(out, sizeof(out), packet);
	CHECK("encode_len", len == (int)sizeof(dns_a_response));
	CHECK("encode_bytes", len == (int)sizeof(dns_a_response) && memcmp(out, dns_a_response, len) == 0);
}

static void test_dns_decode(void)
{
	unsigned char buf[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)buf;
	unsigned char data[sizeof(dns_a_response)];
	char name[DNS_MAX_CNAME_LEN];
	int count = 0, qtype = 0, qclass = 0, ttl = 0;

	memcpy(data, dns_a_response, sizeof(data));
	CHECK("decode_a", dns_decode(packet, sizeof(buf), data, sizeof(data)) == 0);
	CHECK("a_id", packet->head.id == 0x1234);
	CHECK("a_qr", packet->head.qr == DNS_QR_ANSWER);
	CHECK("a_rd_ra", packet->head.rd == 1 && packet->head.ra == 1);
	CHECK("a_rcode", packet->head.rcode == DNS_RC_NOERROR);

	struct dns_rrs *rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &count);
	CHECK("a_qd_count", count == 1 && rrs != NULL);
	if (rrs) {
		CHECK("a_qd_get", dns_get_domain(rrs, name, sizeof(name), &qtype, &qclass) == 0);
		CHECK("a_qd_name", strcmp(name, "example.com") == 0);
		CHECK("a_qd_type", qtype == DNS_T_A && qclass == DNS_C_IN);
	}

	rrs = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	CHECK("a_an_count", count == 1 && rrs != NULL);
	if (rrs) {
		unsigned char addr[DNS_RR_A_LEN] = {0};
		CHECK("a_an_get", dns_get_A(rrs, name, sizeof(name), &ttl, addr) == 0);
		CHECK("a_an_name", strcmp(name, "example.com") == 0);
		CHECK("a_an_ttl", ttl == 300);
		CHECK("a_an_addr", addr[0] == 93 && addr[1] == 184 && addr[2] == 216 && addr[3] == 34);
	}

	memcpy(data, dns_a_response, sizeof(data));
	CHECK("decode_truncated", dns_decode(packet, sizeof(buf), data, sizeof(data) - 1) != 0);
	CHECK("decode_short", dns_decode(packet, sizeof(buf), data, 5) != 0);
}

static void test_dns_cname_aaaa(void)
{
	unsigned char buf[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)buf;
	unsigned char data[sizeof(dns_cname_aaaa)];
	char name[DNS_MAX_CNAME_LEN], cname[DNS_MAX_CNAME_LEN];
	int count = 0, ttl = 0;

	memcpy(data, dns_cname_aaaa, sizeof(data));
	CHECK("decode_cname", dns_decode(packet, sizeof(buf), data, sizeof(data)) == 0);
	CHECK("cname_id", packet->head.id == 0xabcd);

	struct dns_rrs *rrs = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	CHECK("cname_an_count", count == 2 && rrs != NULL);
	if (rrs && count == 2) {
		CHECK("cname_type", rrs->type == DNS_T_CNAME);
		CHECK("cname_get", dns_get_CNAME(rrs, name, sizeof(name), &ttl, cname, sizeof(cname)) == 0);
		CHECK("cname_owner", strcmp(name, "www.example.com") == 0);
		CHECK("cname_target", strcmp(cname, "example.com") == 0);
		CHECK("cname_ttl", ttl == 60);

		rrs = dns_get_rrs_next(packet, rrs);
		CHECK("aaaa_present", rrs != NULL && rrs->type == DNS_T_AAAA);
		if (rrs) {
			unsigned char addr[DNS_RR_AAAA_LEN];
			CHECK("aaaa_get", dns_get_AAAA(rrs, name, sizeof(name), &ttl, addr) == 0);
			CHECK("aaaa_owner", strcmp(name, "example.com") == 0);
			CHECK("aaaa_ttl", ttl == 120);
			CHECK("aaaa_addr", addr[0] == 0x20 && addr[1] == 0x01 && addr[2] == 0x0d && addr[3] == 0xb8 &&
								   addr[15] == 0x01 && addr[7] == 0);
		}
	}

	/* an in-place rewrite changes id and TTLs but keeps the records */
	struct dns_update_param param = {.id = 0x4242, .ip_ttl = 7, .cname_ttl = 9, .query_domain = "www.example.com"};
	CHECK("update", dns_packet_update(data, sizeof(data), &param) == 0);
	CHECK("update_id", data[0] == 0x42 && data[1] == 0x42);
	CHECK("redecode", dns_decode(packet, sizeof(buf), data, sizeof(data)) == 0);
	rrs = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	if (rrs && count == 2) {
		dns_get_CNAME(rrs, name, sizeof(name), &ttl, cname, sizeof(cname));
		CHECK("update_cname_ttl", ttl == 7);
		rrs = dns_get_rrs_next(packet, rrs);
		unsigned char addr[DNS_RR_AAAA_LEN];
		dns_get_AAAA(rrs, name, sizeof(name), &ttl, addr);
		CHECK("update_ip_ttl", ttl == 7);
	}
}

static void test_dns_roundtrip(void)
{
	unsigned char buf[DNS_PACKSIZE], buf2[DNS_PACKSIZE];
	unsigned char out[DNS_IN_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)buf;
	struct dns_packet *packet2 = (struct dns_packet *)buf2;
	struct dns_head head;
	char name[DNS_MAX_CNAME_LEN], text[DNS_MAX_CNAME_LEN];
	int ttl = 0, count = 0;
	unsigned short prio = 0, weight = 0, port = 0;

	memset(&head, 0, sizeof(head));
	head.id = 7;
	head.qr = DNS_QR_ANSWER;
	CHECK("rt_init", dns_packet_init(packet, sizeof(buf), &head) == 0);
	CHECK("rt_q", dns_add_domain(packet, "_sip._tcp.example.org", DNS_T_SRV, DNS_C_IN) == 0);
	CHECK("rt_srv", dns_add_SRV(packet, DNS_RRS_AN, "_sip._tcp.example.org", 30, 10, 20, 5060, "sip.example.org") == 0);
	CHECK("rt_ptr", dns_add_PTR(packet, DNS_RRS_AN, "_sip._tcp.example.org", 30, "host.example.org") == 0);
	int len = dns_encode(out, sizeof(out), packet);
	CHECK("rt_encode", len > 12);
	CHECK("rt_decode", dns_decode(packet2, sizeof(buf2), out, len) == 0);

	struct dns_rrs *rrs = dns_get_rrs_start(packet2, DNS_RRS_AN, &count);
	CHECK("rt_count", count == 2 && rrs != NULL);
	if (rrs && count == 2) {
		CHECK("rt_srv_get", dns_get_SRV(rrs, name, sizeof(name), &ttl, &prio, &weight, &port, text, sizeof(text)) == 0);
		CHECK("rt_srv_vals", prio == 10 && weight == 20 && port == 5060 && ttl == 30);
		CHECK("rt_srv_target", strcmp(text, "sip.example.org") == 0 && strcmp(name, "_sip._tcp.example.org") == 0);
		rrs = dns_get_rrs_next(packet2, rrs);
		CHECK("rt_ptr_get", rrs && dns_get_PTR(rrs, name, sizeof(name), &ttl, text, sizeof(text)) == 0);
		CHECK("rt_ptr_val", strcmp(text, "host.example.org") == 0 && ttl == 30);
	}
}

static void test_http1(void)
{
	static const char req[] = "GET /dns-query?dns=AAABAAAB&ct=x HTTP/1.1\r\nHost: dns.example.com\r\n"
							  "Accept: application/dns-message\r\nContent-Length: 0\r\n\r\n";
	struct http_head *h = http_head_init(4096, HTTP_VERSION_1_1);
	CHECK("h1_init", h != NULL);
	if (!h) {
		return;
	}
	int ret = http_head_parse(h, (const unsigned char *)req, sizeof(req) - 1);
	CHECK("h1_parse_len", ret == (int)sizeof(req) - 1);
	CHECK("h1_type", http_head_get_head_type(h) == HTTP_HEAD_REQUEST);
	CHECK("h1_method", http_head_get_method(h) == HTTP_METHOD_GET);
	const char *url = http_head_get_url(h);
	CHECK("h1_url", url && strcmp(url, "/dns-query") == 0);
	const char *v = http_head_get_params_value(h, "dns");
	CHECK("h1_param_dns", v && strcmp(v, "AAABAAAB") == 0);
	v = http_head_get_params_value(h, "ct");
	CHECK("h1_param_ct", v && strcmp(v, "x") == 0);
	v = http_head_get_fields_value(h, "Host");
	CHECK("h1_host", v && strcmp(v, "dns.example.com") == 0);
	v = http_head_get_fields_value(h, "Accept");
	CHECK("h1_accept", v && strcmp(v, "application/dns-message") == 0);
	CHECK("h1_nodata", http_head_get_data_len(h) == 0);
	http_head_destroy(h);

	static const char rsp[] = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 5\r\n\r\nhello";
	h = http_head_init(4096, HTTP_VERSION_1_1);
	ret = http_head_parse(h, (const unsigned char *)rsp, sizeof(rsp) - 1);
	CHECK("h1_rsp_len", ret == (int)sizeof(rsp) - 1);
	CHECK("h1_rsp_type", http_head_get_head_type(h) == HTTP_HEAD_RESPONSE);
	CHECK("h1_rsp_code", http_head_get_httpcode(h) == 200);
	v = http_head_get_httpcode_msg(h);
	CHECK("h1_rsp_msg", v && strcmp(v, "OK") == 0);
	CHECK("h1_rsp_datalen", http_head_get_data_len(h) == 5);
	const unsigned char *d = http_head_get_data(h);
	CHECK("h1_rsp_data", d && memcmp(d, "hello", 5) == 0);
	http_head_destroy(h);

	h = http_head_init(4096, HTTP_VERSION_1_1);
	ret = http_head_parse(h, (const unsigned char *)"GET / HTTP/1.1\r\nHost: a", 23);
	CHECK("h1_incomplete", ret == -1);
	http_head_destroy(h);
}

struct hdr_acc {
	char text[512];
	int count;
};

static int collect(void *ctx, const char *name, const char *value)
{
	struct hdr_acc *acc = ctx;
	size_t used = strlen(acc->text);
	snprintf(acc->text + used, sizeof(acc->text) - used, "%s=%s;", name, value);
	acc->count++;
	return 0;
}

static void test_hpack(void)
{
	/* RFC 7541 C.2.4: indexed field 2 is :method GET */
	static const uint8_t indexed[] = {0x82};
	/* RFC 7541 C.3.1: first request without Huffman coding */
	static const uint8_t c31[] = {0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
								  '.',  'c',  'o',  'm'};
	/* RFC 7541 C.4.1: same request with Huffman coding */
	static const uint8_t c41[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5,
								  0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
	/* RFC 7541 C.5.1: first response (dynamic table size 256) */
	struct hpack_context ctx;
	struct hdr_acc acc;

	hpack_init_context(&ctx);
	memset(&acc, 0, sizeof(acc));
	CHECK("hpack_indexed", hpack_decode_headers(&ctx, indexed, sizeof(indexed), collect, &acc) >= 0);
	CHECK("hpack_indexed_val", strcmp(acc.text, ":method=GET;") == 0);
	hpack_free_context(&ctx);

	hpack_init_context(&ctx);
	memset(&acc, 0, sizeof(acc));
	CHECK("hpack_c31", hpack_decode_headers(&ctx, c31, sizeof(c31), collect, &acc) >= 0);
	CHECK("hpack_c31_val", strcmp(acc.text, ":method=GET;:scheme=http;:path=/;:authority=www.example.com;") == 0);
	CHECK("hpack_c31_count", acc.count == 4);
	hpack_free_context(&ctx);

	hpack_init_context(&ctx);
	memset(&acc, 0, sizeof(acc));
	CHECK("hpack_c41", hpack_decode_headers(&ctx, c41, sizeof(c41), collect, &acc) >= 0);
	CHECK("hpack_c41_val", strcmp(acc.text, ":method=GET;:scheme=http;:path=/;:authority=www.example.com;") == 0);
	hpack_free_context(&ctx);

	/* literal with incremental indexing goes to the dynamic table (index 62) and is then referenced */
	static const uint8_t c32[] = {0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l',
								  'e',  '.',  'c',  'o',  'm',  0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 'n', 'o', '-', 'c',
								  'a',  'c',  'h',  'e'};
	hpack_init_context(&ctx);
	memset(&acc, 0, sizeof(acc));
	CHECK("hpack_c32", hpack_decode_headers(&ctx, c32, sizeof(c32), collect, &acc) >= 0);
	CHECK("hpack_c32_val",
		  strcmp(acc.text, ":method=GET;:scheme=http;:path=/;:authority=www.example.com;"
						   ":method=GET;:scheme=http;:path=/;:authority=www.example.com;cache-control=no-cache;") == 0);
	hpack_free_context(&ctx);

	/* encoder: :method GET is static index 2 and a literal with indexing is emitted for unknown names */
	uint8_t buf[256];
	hpack_init_context(&ctx);
	int n = hpack_encode_header(&ctx, ":method", "GET", buf, sizeof(buf));
	CHECK("hpack_enc_static", n == 1 && buf[0] == 0x82);
	n = hpack_encode_header(&ctx, "x-custom", "v1", buf, sizeof(buf));
	CHECK("hpack_enc_literal", n > 0);
	memset(&acc, 0, sizeof(acc));
	CHECK("hpack_enc_roundtrip", n > 0 && hpack_decode_headers(&ctx, buf, n, collect, &acc) >= 0);
	CHECK("hpack_enc_val", strcmp(acc.text, "x-custom=v1;") == 0);
	hpack_free_context(&ctx);

	hpack_init_context(&ctx);
	static const uint8_t bad[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	memset(&acc, 0, sizeof(acc));
	CHECK("hpack_bad", hpack_decode_headers(&ctx, bad, sizeof(bad), collect, &acc) < 0);
	hpack_free_context(&ctx);
}

static void test_http3(void)
{
	/* HEADERS frame: QPACK prefix 00 00, :method GET (idx17), :scheme https (idx23), :path /dns-query?dns=AQ
	 * as literal with static name ref idx 1, :authority example.com literal with static name ref idx 0 */
	static const char path[] = "/dns-query?dns=AQ";
	static const char auth[] = "example.com";
	unsigned char frame[128];
	size_t n = 0;
	frame[n++] = 0x01;   /* HEADERS */
	frame[n++] = 0;      /* length, patched below */
	frame[n++] = 0x00;
	frame[n++] = 0x00;
	frame[n++] = 0xd1;   /* indexed static 17 :method GET */
	frame[n++] = 0xd7;   /* indexed static 23 :scheme https */
	frame[n++] = 0x50;   /* literal, static name ref, N=0, index 0 :authority */
	frame[n++] = (unsigned char)(sizeof(auth) - 1);
	memcpy(frame + n, auth, sizeof(auth) - 1);
	n += sizeof(auth) - 1;
	frame[n++] = 0x51;   /* literal, static name ref index 1 :path */
	frame[n++] = (unsigned char)(sizeof(path) - 1);
	memcpy(frame + n, path, sizeof(path) - 1);
	n += sizeof(path) - 1;
	frame[1] = (unsigned char)(n - 2);

	struct http_head *h = http_head_init(4096, HTTP_VERSION_3_0);
	CHECK("h3_init", h != NULL);
	if (!h) {
		return;
	}
	int ret = http_head_parse(h, frame, (int)n);
	CHECK("h3_parse", ret >= 0);
	CHECK("h3_method", http_head_get_method(h) == HTTP_METHOD_GET);
	const char *url = http_head_get_url(h);
	CHECK("h3_url", url && strcmp(url, "/dns-query") == 0);
	const char *v = http_head_get_params_value(h, "dns");
	CHECK("h3_param", v && strcmp(v, "AQ") == 0);
	http_head_destroy(h);

	h = http_head_init(4096, HTTP_VERSION_3_0);
	ret = http_head_parse(h, frame, (int)n - 3);
	CHECK("h3_incomplete", ret == -1);
	http_head_destroy(h);
}

static void test_util(void)
{
	char scheme[32], host[256], path[256], user[128], pass[128];
	int port = 0;

	CHECK("uri_https", parse_uri("https://dns.example.com:8443/dns-query", scheme, host, &port, path) == 0);
	CHECK("uri_https_vals", strcmp(scheme, "https") == 0 && strcmp(host, "dns.example.com") == 0 && port == 8443 &&
								strcmp(path, "/dns-query") == 0);
	CHECK("uri_ext", parse_uri_ext("https://bob:secret@example.org/x", scheme, user, pass, host, &port, path) == 0);
	CHECK("uri_ext_vals", strcmp(user, "bob") == 0 && strcmp(pass, "secret") == 0 && strcmp(host, "example.org") == 0 &&
							  port == -1 && strcmp(path, "/x") == 0);
	char out[64];
	CHECK("urldecode", urldecode(out, sizeof(out), "a%20b%2Fc") >= 0 && strcmp(out, "a b/c") == 0);
	CHECK("ipv4_ok", check_is_ipv4("192.168.1.1") == 0);
	CHECK("ipv4_bad", check_is_ipv4("1.2.3") != 0 && check_is_ipv4("example.com") != 0);
	CHECK("ipv6_ok", check_is_ipv6("2001:db8::1") == 0);
	uint8_t mac[6];
	CHECK("mac", parser_mac_address("aa:bb:cc:00:11:22", mac) == 0 && mac[0] == 0xaa && mac[5] == 0x22);
}

int main(void)
{
	test_dns_encode();
	test_dns_decode();
	test_dns_cname_aaaa();
	test_dns_roundtrip();
	test_http1();
	test_hpack();
	test_http3();
	test_util();
	printf("ORACLE_RESULT passed=%d failed=%d\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
