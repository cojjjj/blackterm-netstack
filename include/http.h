#ifndef BLACKTERM_HTTP_H
#define BLACKTERM_HTTP_H

#include <stddef.h>

#define HTTP_MAX_REQUEST_LEN 4096
#define HTTP_MAX_STATUS_TEXT 64

typedef struct {
    int status_code;
    char status_text[HTTP_MAX_STATUS_TEXT];

    size_t header_len;
    const char *body;
    size_t body_len;
} http_response_t;

size_t http_build_get_request(
    char *buffer,
    size_t buffer_len,
    const char *host,
    const char *path
);

int http_parse_response(
    const char *data,
    size_t data_len,
    http_response_t *response
);

/*
 * Detect whether the response headers contain:
 *
 * Transfer-Encoding: chunked
 *
 * Returns:
 *   1 chunked
 *   0 not chunked
 *  -1 invalid arguments
 */
int http_response_is_chunked(
    const char *data,
    size_t header_len
);

/*
 * Decode an HTTP/1.1 chunked body.
 *
 * Example:
 *
 * 4\r\n
 * Wiki\r\n
 * 5\r\n
 * pedia\r\n
 * 0\r\n
 * \r\n
 *
 * becomes:
 *
 * Wikipedia
 *
 * Returns decoded length on success.
 * Returns 0 on failure.
 */
size_t http_decode_chunked_body(
    const char *input,
    size_t input_len,
    char *output,
    size_t output_len
);

#endif
