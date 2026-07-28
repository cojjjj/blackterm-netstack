#include "dns.h"

#include <string.h>

static uint16_t read_u16_be(
    const uint8_t *data
)
{
    return (uint16_t)(
        ((uint16_t)data[0] << 8) |
        (uint16_t)data[1]
    );
}

static uint32_t read_u32_be(
    const uint8_t *data
)
{
    return
        ((uint32_t)data[0] << 24) |
        ((uint32_t)data[1] << 16) |
        ((uint32_t)data[2] << 8) |
        (uint32_t)data[3];
}

static void write_u16_be(
    uint8_t *data,
    uint16_t value
)
{
    data[0] =
        (uint8_t)((value >> 8) & 0xFF);

    data[1] =
        (uint8_t)(value & 0xFF);
}

/*
 * Skip a DNS encoded name.
 *
 * Supports both ordinary labels:
 *
 * 07 example 03 com 00
 *
 * and compression pointers:
 *
 * C0 0C
 */
static int dns_skip_name(
    const uint8_t *data,
    size_t data_len,
    size_t *offset
)
{
    if (
        data == NULL ||
        offset == NULL ||
        *offset >= data_len
    ) {
        return -1;
    }

    size_t pos = *offset;

    /*
     * Defensive limit against malformed packets.
     */
    size_t labels_seen = 0;

    while (pos < data_len) {
        uint8_t length = data[pos];

        /*
         * Compression pointer.
         */
        if ((length & 0xC0U) == 0xC0U) {
            if (pos + 1 >= data_len) {
                return -1;
            }

            *offset = pos + 2;

            return 0;
        }

        /*
         * Reserved DNS label forms.
         */
        if ((length & 0xC0U) != 0) {
            return -1;
        }

        pos++;

        if (length == 0) {
            *offset = pos;

            return 0;
        }

        if (length > 63) {
            return -1;
        }

        if (
            pos + length >
            data_len
        ) {
            return -1;
        }

        pos += length;

        labels_seen++;

        if (labels_seen > 127) {
            return -1;
        }
    }

    return -1;
}

size_t dns_build_a_query(
    uint8_t *buffer,
    size_t buffer_len,
    uint16_t transaction_id,
    const char *hostname
)
{
    if (
        buffer == NULL ||
        hostname == NULL ||
        hostname[0] == '\0' ||
        buffer_len < DNS_HEADER_LEN
    ) {
        return 0;
    }

    size_t hostname_len =
        strlen(hostname);

    if (
        hostname_len == 0 ||
        hostname_len > 253
    ) {
        return 0;
    }

    memset(
        buffer,
        0,
        buffer_len
    );

    /*
     * Header
     */

    write_u16_be(
        buffer,
        transaction_id
    );

    /*
     * Flags:
     *
     * QR = 0 query
     * RD = 1 recursion desired
     *
     * 0x0100
     */
    buffer[2] = 0x01;
    buffer[3] = 0x00;

    /*
     * QDCOUNT = 1
     */
    write_u16_be(
        buffer + 4,
        1
    );

    size_t offset =
        DNS_HEADER_LEN;

    /*
     * Encode:
     *
     * example.com
     *
     * as:
     *
     * 07 example 03 com 00
     */
    const char *label_start =
        hostname;

    const char *cursor =
        hostname;

    for (;;) {
        if (
            *cursor == '.' ||
            *cursor == '\0'
        ) {
            size_t label_len =
                (size_t)(
                    cursor -
                    label_start
                );

            if (
                label_len == 0 ||
                label_len > 63
            ) {
                return 0;
            }

            if (
                offset +
                1 +
                label_len >
                buffer_len
            ) {
                return 0;
            }

            buffer[offset++] =
                (uint8_t)label_len;

            memcpy(
                buffer + offset,
                label_start,
                label_len
            );

            offset += label_len;

            if (*cursor == '\0') {
                break;
            }

            label_start =
                cursor + 1;
        }

        cursor++;
    }

    if (
        offset + 1 + 4 >
        buffer_len
    ) {
        return 0;
    }

    /*
     * Root terminator.
     */
    buffer[offset++] = 0;

    /*
     * QTYPE = A
     */
    write_u16_be(
        buffer + offset,
        DNS_TYPE_A
    );

    offset += 2;

    /*
     * QCLASS = IN
     */
    write_u16_be(
        buffer + offset,
        DNS_CLASS_IN
    );

    offset += 2;

    return offset;
}

int dns_parse_response(
    const uint8_t *data,
    size_t data_len,
    uint16_t expected_transaction_id,
    dns_response_t *response
)
{
    if (
        data == NULL ||
        response == NULL
    ) {
        return -1;
    }

    if (data_len < DNS_HEADER_LEN) {
        return -2;
    }

    uint16_t transaction_id =
        read_u16_be(data);

    if (
        transaction_id !=
        expected_transaction_id
    ) {
        return -3;
    }

    uint16_t flags =
        read_u16_be(data + 2);

    /*
     * QR must be set for response.
     */
    if ((flags & 0x8000U) == 0) {
        return -4;
    }

    uint16_t question_count =
        read_u16_be(data + 4);

    uint16_t answer_count =
        read_u16_be(data + 6);

    memset(
        response,
        0,
        sizeof(*response)
    );

    response->transaction_id =
        transaction_id;

    response->authoritative =
        (uint8_t)(
            (flags & 0x0400U) != 0
        );

    response->truncated =
        (uint8_t)(
            (flags & 0x0200U) != 0
        );

    response->recursion_available =
        (uint8_t)(
            (flags & 0x0080U) != 0
        );

    response->response_code =
        (uint8_t)(flags & 0x000FU);

    size_t offset =
        DNS_HEADER_LEN;

    /*
     * Skip questions.
     */
    for (
        uint16_t i = 0;
        i < question_count;
        i++
    ) {
        if (
            dns_skip_name(
                data,
                data_len,
                &offset
            ) != 0
        ) {
            return -5;
        }

        /*
         * QTYPE + QCLASS
         */
        if (
            offset + 4 >
            data_len
        ) {
            return -5;
        }

        offset += 4;
    }

    /*
     * Parse answers.
     */
    for (
        uint16_t i = 0;
        i < answer_count;
        i++
    ) {
        if (
            dns_skip_name(
                data,
                data_len,
                &offset
            ) != 0
        ) {
            return -5;
        }

        /*
         * TYPE  2
         * CLASS 2
         * TTL   4
         * RDLEN 2
         */
        if (
            offset + 10 >
            data_len
        ) {
            return -5;
        }

        uint16_t type =
            read_u16_be(
                data + offset
            );

        uint16_t class_code =
            read_u16_be(
                data + offset + 2
            );

        uint32_t ttl =
            read_u32_be(
                data + offset + 4
            );

        uint16_t rdlength =
            read_u16_be(
                data + offset + 8
            );

        offset += 10;

        if (
            offset + rdlength >
            data_len
        ) {
            return -5;
        }

        if (
            type == DNS_TYPE_A &&
            class_code == DNS_CLASS_IN &&
            rdlength == 4
        ) {
            if (
                response->answer_count <
                DNS_MAX_ANSWERS
            ) {
                dns_a_record_t *record =
                    &response->answers[
                        response->answer_count
                    ];

                memcpy(
                    record->address,
                    data + offset,
                    4
                );

                record->ttl =
                    ttl;

                response->answer_count++;
            }
        }

        offset += rdlength;
    }

    return 0;
}

const char *dns_response_code_name(
    uint8_t response_code
)
{
    switch (response_code) {
        case 0:
            return "NOERROR";

        case 1:
            return "FORMERR";

        case 2:
            return "SERVFAIL";

        case 3:
            return "NXDOMAIN";

        case 4:
            return "NOTIMP";

        case 5:
            return "REFUSED";

        default:
            return "UNKNOWN";
    }
}
