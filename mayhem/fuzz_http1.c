/* Parses an HTTP/1.1 request or response head with smartdns' own parser (used by the proxy, DoH server
 * and DoH client paths), then reads every parsed field and serializes the result back. */
#include "smartdns/http_parse.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0 || size > 8192) {
		return -1;
	}

	unsigned char *in = malloc(size);
	if (!in) {
		abort();
	}
	memcpy(in, data, size);

	struct http_head *head = http_head_init(4096, HTTP_VERSION_1_1);
	if (!head) {
		abort();
	}

	int ret = http_head_parse(head, in, (int)size);
	if (ret >= 0) {
		struct http_head_fields *f;
		volatile size_t sink = 0;
		const char *s;

		http_head_get_head_type(head);
		http_method_str(http_head_get_method(head));
		http_head_get_httpcode(head);
		if ((s = http_head_get_url(head))) {
			sink += strlen(s);
		}
		if ((s = http_head_get_httpversion(head))) {
			sink += strlen(s);
		}
		if ((s = http_head_get_httpcode_msg(head))) {
			sink += strlen(s);
		}
		if ((s = http_head_get_fields_value(head, "Content-Type"))) {
			sink += strlen(s);
		}
		if ((s = http_head_get_params_value(head, "dns"))) {
			sink += strlen(s);
		}
		for (f = http_head_first_fields(head); f; f = http_head_next_fields(f)) {
			const char *name = http_head_fields_get_name(f);
			const char *value = http_head_fields_get_value(f);
			if (name && value) {
				sink += strlen(name) + strlen(value);
			}
		}
		const unsigned char *body = http_head_get_data(head);
		int body_len = http_head_get_data_len(head);
		for (int i = 0; body && i < body_len; i++) {
			sink += body[i];
		}

		unsigned char out[8192];
		http_head_serialize(head, out, sizeof(out));
	}

	http_head_destroy(head);
	free(in);
	return ret >= 0 ? 0 : -1;
}
