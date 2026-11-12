/* Drives smartdns' HTTP/2 server connection (the DoH-over-h2 listener) with a fuzzed client byte stream:
 * preface, SETTINGS, HEADERS (HPACK), CONTINUATION, DATA, WINDOW_UPDATE, PING, RST_STREAM, GOAWAY.
 * It follows the server's own poll/accept loop and reads each accepted stream's request. No sockets. */
#include "smartdns/http2.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct feed {
	const uint8_t *data;
	size_t size;
	size_t off;
};

static int bio_read(void *private_data, uint8_t *buf, int len)
{
	struct feed *f = private_data;
	if (f->off >= f->size) {
		errno = EAGAIN;
		return -1;
	}
	size_t n = f->size - f->off;
	if (n > (size_t)len) {
		n = (size_t)len;
	}
	memcpy(buf, f->data + f->off, n);
	f->off += n;
	return (int)n;
}

static int bio_write(void *private_data, const uint8_t *buf, int len)
{
	(void)private_data;
	(void)buf;
	return len;
}

static void walk_cb(void *arg, const char *name, const char *value)
{
	size_t *sink = arg;
	*sink += strlen(name) + strlen(value);
}

static void handle_stream(struct http2_stream *stream)
{
	size_t sink = 0;
	const char *s;
	uint8_t body[512];

	if ((s = http2_stream_get_method(stream))) {
		sink += strlen(s);
	}
	if ((s = http2_stream_get_path(stream))) {
		sink += strlen(s);
	}
	char *dns = http2_stream_get_query_param(stream, "dns");
	if (dns) {
		sink += strlen(dns);
		free(dns);
	}
	if ((s = http2_stream_get_header(stream, "content-type"))) {
		sink += strlen(s);
	}
	http2_stream_headers_walk(stream, walk_cb, &sink);
	http2_stream_get_status(stream);
	http2_stream_get_id(stream);

	int guard = 0;
	while (http2_stream_body_available(stream) > 0 && guard++ < 64) {
		if (http2_stream_read_body(stream, body, sizeof(body)) <= 0) {
			break;
		}
	}
	http2_stream_is_remote_end(stream);

	struct http2_header_pair headers[] = {{"content-type", "application/dns-message"}, {NULL, NULL}};
	if (http2_stream_set_response(stream, 200, headers, 1) == 0) {
		http2_stream_write_body(stream, (const uint8_t *)"abcdef", 6, 1);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 9 || size > 16384) {
		return -1;
	}

	uint8_t *in = malloc(size);
	if (!in) {
		abort();
	}
	memcpy(in, data, size);

	struct feed feed = {in, size, 0};
	struct http2_settings settings = {.max_concurrent_streams = -1};
	struct http2_ctx *ctx = http2_ctx_server_new("fuzz", bio_read, bio_write, &feed, &settings);
	if (!ctx) {
		abort();
	}

	int ret = http2_ctx_handshake(ctx);
	if (ret > 0) {
		for (int loop = 0; loop < 64; loop++) {
			struct http2_poll_item items[16];
			int count = 0;

			memset(items, 0, sizeof(items));
			ret = http2_ctx_poll_readable(ctx, items, 16, &count);
			if (ret < 0 || count == 0) {
				break;
			}
			for (int i = 0; i < count; i++) {
				if (items[i].stream == NULL) {
					struct http2_stream *s;
					int accepted = 0;
					while (items[i].readable && (s = http2_ctx_accept_stream(ctx)) != NULL) {
						handle_stream(s);
						http2_stream_put(s);
						if (++accepted >= 16) {
							break;
						}
					}
					continue;
				}
				if (items[i].readable) {
					handle_stream(items[i].stream);
				}
				http2_stream_put(items[i].stream);
			}
		}
	}

	http2_ctx_close(ctx);
	free(in);
	return ret >= 0 ? 0 : -1;
}
