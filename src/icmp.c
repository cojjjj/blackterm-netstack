#include "icmp.h"

#include <string.h>

static uint16_t read_u16_be(const uint8_t *data)
{
    return (uint16_t)(
        ((uint16_t)data[0] << 8) |
        (uint16_t)data[1]
    );
}

static void write_u16_be(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)((value >> 8) & 0xFF);
    data[1] = (uint8_t)(value & 0xFF);
}

uint16_t icmp_checksum(
    const uint8_t *data,
    size_t data_len
)
{
    if (data == NULL) {
        return 0;
    }

    uint32_t sum = 0;
    size_t i = 0;

    while (i + 1 < data_len) {
        uint16_t word = (uint16_t)(
            ((uint16_t)data[i] << 8) |
            (uint16_t)data[i + 1]
        );

        sum += word;
        sum = (sum & 0xFFFFU) + (sum >> 16);

        i += 2;
    }

    if (i < data_len) {
        sum += (uint32_t)((uint16_t)data[i] << 8);
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }

    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }

    return (uint16_t)(~sum & 0xFFFFU);
}

static int icmp_build_echo(
    icmp_packet_t *packet,
    uint8_t type,
    uint16_t identifier,
    uint16_t sequence,
    const uint8_t *payload,
    size_t payload_len
)
{
    if (packet == NULL) {
        return -1;
    }

    if (payload_len > 0 && payload == NULL) {
        return -1;
    }

    if (payload_len > ICMP_MAX_PAYLOAD_LEN) {
        return -1;
    }

    memset(packet, 0, sizeof(*packet));

    packet->type = type;
    packet->code = ICMP_CODE_ECHO;

    packet->checksum = 0;

    packet->identifier = identifier;
    packet->sequence = sequence;

    packet->payload_len = payload_len;

    if (payload_len > 0) {
        memcpy(
            packet->payload,
            payload,
            payload_len
        );
    }

    return 0;
}

int icmp_build_echo_request(
    icmp_packet_t *packet,
    uint16_t identifier,
    uint16_t sequence,
    const uint8_t *payload,
    size_t payload_len
)
{
    return icmp_build_echo(
        packet,
        ICMP_TYPE_ECHO_REQUEST,
        identifier,
        sequence,
        payload,
        payload_len
    );
}

int icmp_build_echo_reply(
    icmp_packet_t *packet,
    uint16_t identifier,
    uint16_t sequence,
    const uint8_t *payload,
    size_t payload_len
)
{
    return icmp_build_echo(
        packet,
        ICMP_TYPE_ECHO_REPLY,
        identifier,
        sequence,
        payload,
        payload_len
    );
}

size_t icmp_serialize(
    const icmp_packet_t *packet,
    uint8_t *buffer,
    size_t buffer_len
)
{
    if (packet == NULL || buffer == NULL) {
        return 0;
    }

    if (
        packet->type != ICMP_TYPE_ECHO_REQUEST &&
        packet->type != ICMP_TYPE_ECHO_REPLY
    ) {
        return 0;
    }

    if (packet->code != ICMP_CODE_ECHO) {
        return 0;
    }

    if (packet->payload_len > ICMP_MAX_PAYLOAD_LEN) {
        return 0;
    }

    size_t total_len =
        ICMP_ECHO_HEADER_LEN + packet->payload_len;

    if (buffer_len < total_len) {
        return 0;
    }

    memset(buffer, 0, total_len);

    buffer[0] = packet->type;
    buffer[1] = packet->code;

    buffer[2] = 0;
    buffer[3] = 0;

    write_u16_be(
        buffer + 4,
        packet->identifier
    );

    write_u16_be(
        buffer + 6,
        packet->sequence
    );

    if (packet->payload_len > 0) {
        memcpy(
            buffer + ICMP_ECHO_HEADER_LEN,
            packet->payload,
            packet->payload_len
        );
    }

    uint16_t checksum =
        icmp_checksum(buffer, total_len);

    write_u16_be(
        buffer + 2,
        checksum
    );

    return total_len;
}

int icmp_parse(
    const uint8_t *data,
    size_t data_len,
    icmp_packet_t *packet
)
{
    if (data == NULL || packet == NULL) {
        return -1;
    }

    if (data_len < ICMP_ECHO_HEADER_LEN) {
        return -2;
    }

    uint8_t type = data[0];
    uint8_t code = data[1];

    if (
        type != ICMP_TYPE_ECHO_REQUEST &&
        type != ICMP_TYPE_ECHO_REPLY
    ) {
        return -3;
    }

    if (code != ICMP_CODE_ECHO) {
        return -4;
    }

    if (icmp_checksum(data, data_len) != 0) {
        return -5;
    }

    size_t payload_len =
        data_len - ICMP_ECHO_HEADER_LEN;

    if (payload_len > ICMP_MAX_PAYLOAD_LEN) {
        return -6;
    }

    memset(packet, 0, sizeof(*packet));

    packet->type = type;
    packet->code = code;

    packet->checksum =
        read_u16_be(data + 2);

    packet->identifier =
        read_u16_be(data + 4);

    packet->sequence =
        read_u16_be(data + 6);

    packet->payload_len = payload_len;

    if (payload_len > 0) {
        memcpy(
            packet->payload,
            data + ICMP_ECHO_HEADER_LEN,
            payload_len
        );
    }

    return 0;
}

const char *icmp_type_name(uint8_t type)
{
    switch (type) {
        case ICMP_TYPE_ECHO_REPLY:
            return "Echo Reply";

        case ICMP_TYPE_ECHO_REQUEST:
            return "Echo Request";

        default:
            return "Unknown";
    }
}
