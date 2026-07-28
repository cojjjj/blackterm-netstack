#include "http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t http_build_get_request(
    char *buffer,
    size_t buffer_len,
    const char *host,
    const char *path
)
{
    if (
        buffer == NULL ||
        host == NULL ||
        path == NULL ||
        host[0] == '\0' ||
        path[0] == '\0'
    ) {
        return 0;
    }

    int written = snprintf(
        buffer,
        buffer_len,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: BLACKTERM-NETSTACK/0.1\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        path,
        host
    );

    if (
        written < 0 ||
        (size_t)written >= buffer_len
    ) {
        return 0;
    }

    return (size_t)written;
}

int http_parse_response(
    const char *data,
    size_t data_len,
    http_response_t *response
)
{
    if (
        data == NULL ||
        response == NULL ||
        data_len == 0
    ) {
        return -1;
    }

    memset(
        response,
        0,
        sizeof(*response)
    );

    const char *line_end =
        strstr(data, "\r\n");

    if (line_end == NULL) {
        return -2;
    }

    size_t status_line_len =
        (size_t)(line_end - data);

    if (
        status_line_len < 12 ||
        strncmp(
            data,
            "HTTP/",
            5
        ) != 0
    ) {
        return -2;
    }

    const char *space =
        strchr(data, ' ');

    if (
        space == NULL ||
        space >= line_end
    ) {
        return -2;
    }

    char *endptr = NULL;

    long status =
        strtol(
            space + 1,
            &endptr,
            10
        );

    if (
        endptr == space + 1 ||
        status < 100 ||
        status > 999
    ) {
        return -2;
    }

    response->status_code =
        (int)status;

    if (
        endptr < line_end &&
        *endptr == ' '
    ) {
        const char *text =
            endptr + 1;

        size_t text_len =
            (size_t)(
                line_end - text
            );

        if (
            text_len >=
            sizeof(
                response->status_text
            )
        ) {
            text_len =
                sizeof(
                    response->status_text
                ) - 1;
        }

        memcpy(
            response->status_text,
            text,
            text_len
        );

        response
            ->status_text[text_len] =
            '\0';
    }

    const char *header_end =
        strstr(
            data,
            "\r\n\r\n"
        );

    if (header_end == NULL) {
        return -3;
    }

    response->header_len =
        (size_t)(
            header_end -
            data
        ) + 4;

    if (
        response->header_len >
        data_len
    ) {
        return -3;
    }

    response->body =
        data +
        response->header_len;

    response->body_len =
        data_len -
        response->header_len;

    return 0;
}
