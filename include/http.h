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

/*
 * Build a basic HTTP/1.1 GET request.
 *
 * Returns number of bytes written or 0 on failure.
 */
size_t http_build_get_request(
    char *buffer,
    size_t buffer_len,
    const char *host,
    const char *path
);

/*
 * Parse an HTTP response already stored in memory.
 *
 * Returns:
 *   0 success
 *  -1 invalid arguments
 *  -2 malformed status line
 *  -3 incomplete headers
 */
int http_parse_response(
    const char *data,
    size_t data_len,
    http_response_t *response
);

#endif
