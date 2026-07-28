#include "http.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
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
        strncmp(data, "HTTP/", 5) != 0
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

static int ascii_equal_nocase(
    char a,
    char b
)
{
    return
        tolower((unsigned char)a) ==
        tolower((unsigned char)b);
}

static int header_name_matches(
    const char *line,
    size_t line_len,
    const char *name
)
{
    size_t name_len =
        strlen(name);

    if (
        line_len < name_len + 1
    ) {
        return 0;
    }

    for (
        size_t i = 0;
        i < name_len;
        i++
    ) {
        if (
            !ascii_equal_nocase(
                line[i],
                name[i]
            )
        ) {
            return 0;
        }
    }

    return line[name_len] == ':';
}

static int value_contains_chunked(
    const char *value,
    size_t value_len
)
{
    static const char needle[] =
        "chunked";

    size_t needle_len =
        sizeof(needle) - 1;

    if (
        value_len <
        needle_len
    ) {
        return 0;
    }

    for (
        size_t i = 0;
        i + needle_len <= value_len;
        i++
    ) {
        int match = 1;

        for (
            size_t j = 0;
            j < needle_len;
            j++
        ) {
            if (
                !ascii_equal_nocase(
                    value[i + j],
                    needle[j]
                )
            ) {
                match = 0;
                break;
            }
        }

        if (match) {
            return 1;
        }
    }

    return 0;
}

int http_response_is_chunked(
    const char *data,
    size_t header_len
)
{
    if (
        data == NULL ||
        header_len == 0
    ) {
        return -1;
    }

    const char *cursor =
        data;

    const char *end =
        data + header_len;

    const char *first_line_end =
        strstr(
            cursor,
            "\r\n"
        );

    if (
        first_line_end == NULL ||
        first_line_end >= end
    ) {
        return 0;
    }

    cursor =
        first_line_end + 2;

    while (
        cursor < end
    ) {
        const char *line_end =
            strstr(
                cursor,
                "\r\n"
            );

        if (
            line_end == NULL ||
            line_end > end
        ) {
            break;
        }

        size_t line_len =
            (size_t)(
                line_end -
                cursor
            );

        if (line_len == 0) {
            break;
        }

        if (
            header_name_matches(
                cursor,
                line_len,
                "Transfer-Encoding"
            )
        ) {
            const char *colon =
                memchr(
                    cursor,
                    ':',
                    line_len
                );

            if (colon == NULL) {
                return 0;
            }

            const char *value =
                colon + 1;

            size_t value_len =
                (size_t)(
                    line_end -
                    value
                );

            return
                value_contains_chunked(
                    value,
                    value_len
                );
        }

        cursor =
            line_end + 2;
    }

    return 0;
}

static int hex_value(
    char c
)
{
    if (
        c >= '0' &&
        c <= '9'
    ) {
        return c - '0';
    }

    if (
        c >= 'a' &&
        c <= 'f'
    ) {
        return
            10 +
            (c - 'a');
    }

    if (
        c >= 'A' &&
        c <= 'F'
    ) {
        return
            10 +
            (c - 'A');
    }

    return -1;
}

static int parse_chunk_size(
    const char *line,
    size_t line_len,
    size_t *chunk_size
)
{
    if (
        line == NULL ||
        chunk_size == NULL ||
        line_len == 0
    ) {
        return -1;
    }

    size_t value = 0;
    int saw_digit = 0;

    for (
        size_t i = 0;
        i < line_len;
        i++
    ) {
        char c =
            line[i];

        /*
         * Chunk extensions begin after ';'.
         */
        if (c == ';') {
            break;
        }

        if (
            c == ' ' ||
            c == '\t'
        ) {
            continue;
        }

        int digit =
            hex_value(c);

        if (digit < 0) {
            return -1;
        }

        if (
            value >
            (SIZE_MAX -
            (size_t)digit) /
            16U
        ) {
            return -1;
        }

        value =
            (value * 16U) +
            (size_t)digit;

        saw_digit = 1;
    }

    if (!saw_digit) {
        return -1;
    }

    *chunk_size =
        value;

    return 0;
}

size_t http_decode_chunked_body(
    const char *input,
    size_t input_len,
    char *output,
    size_t output_len
)
{
    if (
        input == NULL ||
        output == NULL ||
        output_len == 0
    ) {
        return 0;
    }

    size_t input_offset = 0;
    size_t output_offset = 0;

    while (
        input_offset <
        input_len
    ) {
        const char *line =
            input +
            input_offset;

        const char *line_end =
            NULL;

        for (
            size_t i =
                input_offset;
            i + 1 <
                input_len;
            i++
        ) {
            if (
                input[i] == '\r' &&
                input[i + 1] == '\n'
            ) {
                line_end =
                    input + i;
                break;
            }
        }

        if (line_end == NULL) {
            return 0;
        }

        size_t line_len =
            (size_t)(
                line_end -
                line
            );

        size_t chunk_size = 0;

        if (
            parse_chunk_size(
                line,
                line_len,
                &chunk_size
            ) != 0
        ) {
            return 0;
        }

        input_offset =
            (size_t)(
                line_end -
                input
            ) + 2;

        if (chunk_size == 0) {
            /*
             * End of chunked body.
             *
             * Trailer headers may follow, but for this
             * first version we only care about the body.
             */
            if (
                output_offset >=
                output_len
            ) {
                return 0;
            }

            output[output_offset] =
                '\0';

            return output_offset;
        }

        if (
            chunk_size >
            input_len -
            input_offset
        ) {
            return 0;
        }

        if (
            chunk_size >
            output_len -
            output_offset -
            1
        ) {
            return 0;
        }

        memcpy(
            output +
            output_offset,
            input +
            input_offset,
            chunk_size
        );

        output_offset +=
            chunk_size;

        input_offset +=
            chunk_size;

        /*
         * Chunk data must be followed by CRLF.
         */
        if (
            input_offset + 2 >
            input_len ||
            input[input_offset] !=
            '\r' ||
            input[input_offset + 1] !=
            '\n'
        ) {
            return 0;
        }

        input_offset += 2;
    }

    return 0;
}
