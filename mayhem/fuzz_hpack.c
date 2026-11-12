/* Decodes an HTTP/2 HPACK header block (static + dynamic table, Huffman strings, table-size updates)
 * with smartdns' own HPACK implementation. The first input byte picks a dynamic table size limit. */
#include "hpack.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int on_header(void *ctx, const char *name, const char *value)
{
	size_t *sink = ctx;
	*sink += strlen(name) + strlen(value);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2 || size > 8192) {
		return -1;
	}

	size_t table = (size_t)data[0] * 64;
	data++;
	size--;

	uint8_t *in = malloc(size);
	if (!in) {
		abort();
	}
	memcpy(in, data, size);

	struct hpack_context hpack;
	size_t sink = 0;
	hpack_init_context(&hpack);
	hpack_resize_dynamic_table(&hpack, table);
	int ret = hpack_decode_headers(&hpack, in, (int)size, on_header, &sink);
	/* decode twice so entries added to the dynamic table by the first pass are referenced by the second */
	if (ret >= 0) {
		ret = hpack_decode_headers(&hpack, in, (int)size, on_header, &sink);
	}
	hpack_free_context(&hpack);
	free(in);
	return ret >= 0 ? 0 : -1;
}
