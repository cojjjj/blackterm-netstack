#include "ipv4.h"

#include <stdio.h>
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

uint16_t ipv4_checksum(
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

        /*
         * Fold carries back into the low 16 bits.
         */
        sum = (sum & 0xFFFFU) + (sum >> 16);

        i += 2;
    }

    /*
     * IPv4 headers are normally even-sized, but support
     * odd buffers so this function remains generally useful.
     */
    if (i < data_len) {
        sum += (uint32_t)((uint16_t)data[i] << 8);

        sum = (sum & 0xFFFFU) + (sum >> 16);
    }

    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }

    return (uint16_t)(~sum & 0xFFFFU);
}

int ipv4_parse(
    const uint8_t *data,
    size_t data_len,
    ipv4_packet_t *packet
)
{
    if (data == NULL || packet == NULL) {
        return -1;
    }

    if (data_len < IPV4_MIN_HEADER_LEN) {
        return -2;
    }

    uint8_t version = (uint8_t)(data[0] >> 4);
    uint8_t ihl = (uint8_t)(data[0] & 0x0F);

    if (version != IPV4_VERSION) {
        return -3;
    }

    if (ihl < IPV4_MIN_IHL || ihl > 15) {
        return -4;
    }

    size_t header_len = (size_t)ihl * 4U;

    if (data_len < header_len) {
        return -4;
    }

    uint16_t total_length = read_u16_be(data + 2);

    if (
        total_length < header_len ||
        total_length > data_len
    ) {
        return -5;
    }

    /*
     * A valid IPv4 header including its checksum should
     * produce a checksum result of zero.
     */
    if (ipv4_checksum(data, header_len) != 0) {
        return -6;
    }

    size_t payload_len =
        (size_t)total_length - header_len;

    if (payload_len > IPV4_MAX_PAYLOAD_LEN) {
        return -7;
    }

    memset(packet, 0, sizeof(*packet));

    packet->version = version;
    packet->ihl = ihl;

    packet->dscp = (uint8_t)(data[1] >> 2);
    packet->ecn = (uint8_t)(data[1] & 0x03);

    packet->total_length = total_length;
    packet->identification = read_u16_be(data + 4);

    uint16_t flags_fragment =
        read_u16_be(data + 6);

    packet->flags =
        (uint8_t)((flags_fragment >> 13) & 0x07);

    packet->fragment_offset =
        (uint16_t)(flags_fragment & 0x1FFF);

    packet->ttl = data[8];
    packet->protocol = data[9];

    packet->header_checksum =
        read_u16_be(data + 10);

    memcpy(
        packet->source_ip,
        data + 12,
        IPV4_ADDR_LEN
    );

    memcpy(
        packet->destination_ip,
        data + 16,
        IPV4_ADDR_LEN
    );

    packet->options_len =
        header_len - IPV4_MIN_HEADER_LEN;

    if (packet->options_len > 0) {
        memcpy(
            packet->options,
            data + IPV4_MIN_HEADER_LEN,
            packet->options_len
        );
    }

    packet->payload_len = payload_len;

    if (payload_len > 0) {
        memcpy(
            packet->payload,
            data + header_len,
            payload_len
        );
    }

    return 0;
}

size_t ipv4_serialize(
    const ipv4_packet_t *packet,
    uint8_t *buffer,
    size_t buffer_len
)
{
    if (packet == NULL || buffer == NULL) {
        return 0;
    }

    if (packet->version != IPV4_VERSION) {
        return 0;
    }

    if (
        packet->ihl < IPV4_MIN_IHL ||
        packet->ihl > 15
    ) {
        return 0;
    }

    size_t header_len =
        (size_t)packet->ihl * 4U;

    size_t expected_options_len =
        header_len - IPV4_MIN_HEADER_LEN;

    if (packet->options_len != expected_options_len) {
        return 0;
    }

    if (packet->payload_len > IPV4_MAX_PAYLOAD_LEN) {
        return 0;
    }

    size_t total_len =
        header_len + packet->payload_len;

    if (
        total_len > IPV4_MAX_PACKET_LEN ||
        buffer_len < total_len
    ) {
        return 0;
    }

    memset(buffer, 0, total_len);

    buffer[0] = (uint8_t)(
        (packet->version << 4) |
        (packet->ihl & 0x0F)
    );

    buffer[1] = (uint8_t)(
        ((packet->dscp & 0x3F) << 2) |
        (packet->ecn & 0x03)
    );

    write_u16_be(
        buffer + 2,
        (uint16_t)total_len
    );

    write_u16_be(
        buffer + 4,
        packet->identification
    );

    uint16_t flags_fragment = (uint16_t)(
        ((uint16_t)(packet->flags & 0x07) << 13) |
        (packet->fragment_offset & 0x1FFF)
    );

    write_u16_be(
        buffer + 6,
        flags_fragment
    );

    buffer[8] = packet->ttl;
    buffer[9] = packet->protocol;

    /*
     * Checksum bytes must be zero while calculating.
     */
    buffer[10] = 0;
    buffer[11] = 0;

    memcpy(
        buffer + 12,
        packet->source_ip,
        IPV4_ADDR_LEN
    );

    memcpy(
        buffer + 16,
        packet->destination_ip,
        IPV4_ADDR_LEN
    );

    if (packet->options_len > 0) {
        memcpy(
            buffer + IPV4_MIN_HEADER_LEN,
            packet->options,
            packet->options_len
        );
    }

    uint16_t checksum =
        ipv4_checksum(buffer, header_len);

    write_u16_be(
        buffer + 10,
        checksum
    );

    if (packet->payload_len > 0) {
        memcpy(
            buffer + header_len,
            packet->payload,
            packet->payload_len
        );
    }

    return total_len;
}

int ipv4_build(
    ipv4_packet_t *packet,
    const uint8_t source_ip[IPV4_ADDR_LEN],
    const uint8_t destination_ip[IPV4_ADDR_LEN],
    uint8_t protocol,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t ttl,
    uint16_t identification
)
{
    if (
        packet == NULL ||
        source_ip == NULL ||
        destination_ip == NULL
    ) {
        return -1;
    }

    if (payload_len > 0 && payload == NULL) {
        return -1;
    }

    if (payload_len > IPV4_MAX_PAYLOAD_LEN) {
        return -1;
    }

    memset(packet, 0, sizeof(*packet));

    packet->version = IPV4_VERSION;
    packet->ihl = IPV4_MIN_IHL;

    packet->dscp = 0;
    packet->ecn = 0;

    packet->total_length = (uint16_t)(
        IPV4_MIN_HEADER_LEN + payload_len
    );

    packet->identification = identification;

    packet->flags = IPV4_FLAG_DF;
    packet->fragment_offset = 0;

    packet->ttl = ttl;
    packet->protocol = protocol;

    packet->header_checksum = 0;

    memcpy(
        packet->source_ip,
        source_ip,
        IPV4_ADDR_LEN
    );

    memcpy(
        packet->destination_ip,
        destination_ip,
        IPV4_ADDR_LEN
    );

    packet->options_len = 0;
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

int ipv4_address_to_string(
    const uint8_t ip[IPV4_ADDR_LEN],
    char *buffer,
    size_t buffer_len
)
{
    if (ip == NULL || buffer == NULL) {
        return -1;
    }

    if (buffer_len < 16) {
        return -1;
    }

    int written = snprintf(
        buffer,
        buffer_len,
        "%u.%u.%u.%u",
        (unsigned int)ip[0],
        (unsigned int)ip[1],
        (unsigned int)ip[2],
        (unsigned int)ip[3]
    );

    if (written < 7 || written > 15) {
        return -1;
    }

    return 0;
}

const char *ipv4_protocol_name(uint8_t protocol)
{
    switch (protocol) {
        case IPV4_PROTOCOL_ICMP:
            return "ICMP";

        case IPV4_PROTOCOL_TCP:
            return "TCP";

        case IPV4_PROTOCOL_UDP:
            return "UDP";

        default:
            return "Unknown";
    }
}
