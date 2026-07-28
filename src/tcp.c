#include "tcp.h"

#include <limits.h>
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

static void write_u32_be(
    uint8_t *data,
    uint32_t value
)
{
    data[0] =
        (uint8_t)((value >> 24) & 0xFF);

    data[1] =
        (uint8_t)((value >> 16) & 0xFF);

    data[2] =
        (uint8_t)((value >> 8) & 0xFF);

    data[3] =
        (uint8_t)(value & 0xFF);
}

static uint32_t checksum_add(
    uint32_t sum,
    uint16_t value
)
{
    sum += value;

    return
        (sum & 0xFFFFU) +
        (sum >> 16);
}

static uint16_t checksum_finish(
    uint32_t sum
)
{
    while ((sum >> 16) != 0U) {
        sum =
            (sum & 0xFFFFU) +
            (sum >> 16);
    }

    return (uint16_t)(
        ~sum & 0xFFFFU
    );
}

int tcp_build(
    tcp_segment_t *segment,
    uint16_t source_port,
    uint16_t destination_port,
    uint32_t sequence_number,
    uint32_t acknowledgment_number,
    uint8_t flags,
    uint16_t window_size,
    const uint8_t *payload,
    size_t payload_len
)
{
    if (segment == NULL) {
        return -1;
    }

    if (
        payload_len > 0 &&
        payload == NULL
    ) {
        return -1;
    }

    if (
        payload_len >
        TCP_MAX_PAYLOAD_LEN
    ) {
        return -1;
    }

    memset(
        segment,
        0,
        sizeof(*segment)
    );

    segment->source_port =
        source_port;

    segment->destination_port =
        destination_port;

    segment->sequence_number =
        sequence_number;

    segment->acknowledgment_number =
        acknowledgment_number;

    segment->data_offset = 5;

    segment->flags =
        flags;

    segment->window_size =
        window_size;

    segment->checksum = 0;

    segment->urgent_pointer = 0;

    segment->options_len = 0;

    segment->payload_len =
        payload_len;

    if (payload_len > 0) {
        memcpy(
            segment->payload,
            payload,
            payload_len
        );
    }

    return 0;
}

int tcp_parse(
    const uint8_t *data,
    size_t data_len,
    tcp_segment_t *segment
)
{
    if (
        data == NULL ||
        segment == NULL
    ) {
        return -1;
    }

    if (
        data_len <
        TCP_MIN_HEADER_LEN
    ) {
        return -2;
    }

    uint8_t data_offset =
        (uint8_t)(
            data[12] >> 4
        );

    if (
        data_offset < 5 ||
        data_offset > 15
    ) {
        return -3;
    }

    size_t header_len =
        (size_t)data_offset * 4U;

    if (
        header_len >
        data_len
    ) {
        return -3;
    }

    size_t payload_len =
        data_len - header_len;

    if (
        payload_len >
        TCP_MAX_PAYLOAD_LEN
    ) {
        return -4;
    }

    memset(
        segment,
        0,
        sizeof(*segment)
    );

    segment->source_port =
        read_u16_be(data);

    segment->destination_port =
        read_u16_be(data + 2);

    segment->sequence_number =
        read_u32_be(data + 4);

    segment->acknowledgment_number =
        read_u32_be(data + 8);

    segment->data_offset =
        data_offset;

    segment->flags =
        data[13];

    segment->window_size =
        read_u16_be(data + 14);

    segment->checksum =
        read_u16_be(data + 16);

    segment->urgent_pointer =
        read_u16_be(data + 18);

    segment->options_len =
        header_len -
        TCP_MIN_HEADER_LEN;

    if (
        segment->options_len >
        0
    ) {
        memcpy(
            segment->options,
            data + TCP_MIN_HEADER_LEN,
            segment->options_len
        );
    }

    segment->payload_len =
        payload_len;

    if (
        payload_len >
        0
    ) {
        memcpy(
            segment->payload,
            data + header_len,
            payload_len
        );
    }

    return 0;
}

size_t tcp_serialize(
    const tcp_segment_t *segment,
    uint8_t *buffer,
    size_t buffer_len
)
{
    if (
        segment == NULL ||
        buffer == NULL
    ) {
        return 0;
    }

    if (
        segment->data_offset < 5 ||
        segment->data_offset > 15
    ) {
        return 0;
    }

    size_t header_len =
        (size_t)
        segment->data_offset *
        4U;

    size_t expected_options_len =
        header_len -
        TCP_MIN_HEADER_LEN;

    if (
        segment->options_len !=
        expected_options_len
    ) {
        return 0;
    }

    size_t total_len =
        header_len +
        segment->payload_len;

    if (
        total_len >
        TCP_MAX_PACKET_LEN ||
        buffer_len <
        total_len
    ) {
        return 0;
    }

    memset(
        buffer,
        0,
        total_len
    );

    write_u16_be(
        buffer,
        segment->source_port
    );

    write_u16_be(
        buffer + 2,
        segment->destination_port
    );

    write_u32_be(
        buffer + 4,
        segment->sequence_number
    );

    write_u32_be(
        buffer + 8,
        segment->acknowledgment_number
    );

    buffer[12] =
        (uint8_t)(
            segment->data_offset << 4
        );

    buffer[13] =
        segment->flags;

    write_u16_be(
        buffer + 14,
        segment->window_size
    );

    write_u16_be(
        buffer + 16,
        segment->checksum
    );

    write_u16_be(
        buffer + 18,
        segment->urgent_pointer
    );

    if (
        segment->options_len >
        0
    ) {
        memcpy(
            buffer +
            TCP_MIN_HEADER_LEN,
            segment->options,
            segment->options_len
        );
    }

    if (
        segment->payload_len >
        0
    ) {
        memcpy(
            buffer +
            header_len,
            segment->payload,
            segment->payload_len
        );
    }

    return total_len;
}

static uint32_t add_bytes(
    uint32_t sum,
    const uint8_t *data,
    size_t length
)
{
    size_t i = 0;

    while (
        i + 1 <
        length
    ) {
        sum =
            checksum_add(
                sum,
                (uint16_t)(
                    ((uint16_t)data[i] << 8) |
                    data[i + 1]
                )
            );

        i += 2;
    }

    if (i < length) {
        sum =
            checksum_add(
                sum,
                (uint16_t)(
                    (uint16_t)data[i] <<
                    8
                )
            );
    }

    return sum;
}

static uint32_t tcp_checksum_sum_ipv4(
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    const uint8_t *tcp_data,
    size_t tcp_len
)
{
    uint32_t sum = 0;

    sum =
        add_bytes(
            sum,
            source_ip,
            4
        );

    sum =
        add_bytes(
            sum,
            destination_ip,
            4
        );

    /*
     * Zero + TCP protocol number 6.
     */
    sum =
        checksum_add(
            sum,
            0x0006
        );

    sum =
        checksum_add(
            sum,
            (uint16_t)tcp_len
        );

    sum =
        add_bytes(
            sum,
            tcp_data,
            tcp_len
        );

    return sum;
}

uint16_t tcp_checksum_ipv4(
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    const uint8_t *tcp_data,
    size_t tcp_len
)
{
    if (
        source_ip == NULL ||
        destination_ip == NULL ||
        tcp_data == NULL ||
        tcp_len <
        TCP_MIN_HEADER_LEN ||
        tcp_len >
        UINT16_MAX
    ) {
        return 0;
    }

    uint16_t result =
        checksum_finish(
            tcp_checksum_sum_ipv4(
                source_ip,
                destination_ip,
                tcp_data,
                tcp_len
            )
        );

    /*
     * A transmitted TCP checksum cannot
     * be represented as "disabled".
     */
    if (result == 0) {
        return 0xFFFF;
    }

    return result;
}

size_t tcp_serialize_ipv4(
    const tcp_segment_t *segment,
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    uint8_t *buffer,
    size_t buffer_len
)
{
    if (
        segment == NULL ||
        source_ip == NULL ||
        destination_ip == NULL ||
        buffer == NULL
    ) {
        return 0;
    }

    tcp_segment_t temporary =
        *segment;

    temporary.checksum = 0;

    size_t tcp_len =
        tcp_serialize(
            &temporary,
            buffer,
            buffer_len
        );

    if (tcp_len == 0) {
        return 0;
    }

    uint16_t checksum =
        tcp_checksum_ipv4(
            source_ip,
            destination_ip,
            buffer,
            tcp_len
        );

    if (checksum == 0) {
        return 0;
    }

    write_u16_be(
        buffer + 16,
        checksum
    );

    return tcp_len;
}

int tcp_checksum_ipv4_valid(
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    const uint8_t *tcp_data,
    size_t tcp_len
)
{
    if (
        source_ip == NULL ||
        destination_ip == NULL ||
        tcp_data == NULL ||
        tcp_len <
        TCP_MIN_HEADER_LEN ||
        tcp_len >
        UINT16_MAX
    ) {
        return 0;
    }

    uint16_t result =
        checksum_finish(
            tcp_checksum_sum_ipv4(
                source_ip,
                destination_ip,
                tcp_data,
                tcp_len
            )
        );

    return result == 0;
}

const char *tcp_state_flag_name(
    uint8_t flags
)
{
    if (
        (flags &
        (TCP_FLAG_SYN | TCP_FLAG_ACK)) ==
        (TCP_FLAG_SYN | TCP_FLAG_ACK)
    ) {
        return "SYN-ACK";
    }

    if (
        (flags & TCP_FLAG_SYN) != 0
    ) {
        return "SYN";
    }

    if (
        (flags & TCP_FLAG_RST) != 0
    ) {
        return "RST";
    }

    if (
        (flags & TCP_FLAG_FIN) != 0
    ) {
        return "FIN";
    }

    if (
        (flags & TCP_FLAG_ACK) != 0
    ) {
        return "ACK";
    }

    return "NONE";
}
