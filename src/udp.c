#include "udp.h"

#include <string.h>

static uint16_t read_u16_be(const uint8_t *data)
{
    return (uint16_t)(
        ((uint16_t)data[0] << 8) |
        (uint16_t)data[1]
    );
}

static void write_u16_be(
    uint8_t *data,
    uint16_t value
)
{
    data[0] = (uint8_t)((value >> 8) & 0xFF);
    data[1] = (uint8_t)(value & 0xFF);
}

static uint32_t checksum_add_word(
    uint32_t sum,
    uint16_t word
)
{
    sum += word;

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

    return (uint16_t)(~sum & 0xFFFFU);
}

int udp_build(
    udp_packet_t *packet,
    uint16_t source_port,
    uint16_t destination_port,
    const uint8_t *payload,
    size_t payload_len
)
{
    if (packet == NULL) {
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
        UDP_MAX_PAYLOAD_LEN
    ) {
        return -1;
    }

    memset(
        packet,
        0,
        sizeof(*packet)
    );

    packet->source_port =
        source_port;

    packet->destination_port =
        destination_port;

    packet->length =
        (uint16_t)(
            UDP_HEADER_LEN +
            payload_len
        );

    packet->checksum =
        0;

    packet->payload_len =
        payload_len;

    if (payload_len > 0) {
        memcpy(
            packet->payload,
            payload,
            payload_len
        );
    }

    return 0;
}

int udp_parse(
    const uint8_t *data,
    size_t data_len,
    udp_packet_t *packet
)
{
    if (
        data == NULL ||
        packet == NULL
    ) {
        return -1;
    }

    if (
        data_len <
        UDP_HEADER_LEN
    ) {
        return -2;
    }

    uint16_t length =
        read_u16_be(data + 4);

    if (
        length <
        UDP_HEADER_LEN ||
        length >
        data_len
    ) {
        return -3;
    }

    size_t payload_len =
        (size_t)length -
        UDP_HEADER_LEN;

    if (
        payload_len >
        UDP_MAX_PAYLOAD_LEN
    ) {
        return -4;
    }

    memset(
        packet,
        0,
        sizeof(*packet)
    );

    packet->source_port =
        read_u16_be(data);

    packet->destination_port =
        read_u16_be(data + 2);

    packet->length =
        length;

    packet->checksum =
        read_u16_be(data + 6);

    packet->payload_len =
        payload_len;

    if (payload_len > 0) {
        memcpy(
            packet->payload,
            data + UDP_HEADER_LEN,
            payload_len
        );
    }

    return 0;
}

size_t udp_serialize(
    const udp_packet_t *packet,
    uint8_t *buffer,
    size_t buffer_len
)
{
    if (
        packet == NULL ||
        buffer == NULL
    ) {
        return 0;
    }

    if (
        packet->payload_len >
        UDP_MAX_PAYLOAD_LEN
    ) {
        return 0;
    }

    size_t total_len =
        UDP_HEADER_LEN +
        packet->payload_len;

    if (
        total_len >
        UDP_MAX_PACKET_LEN ||
        buffer_len <
        total_len
    ) {
        return 0;
    }

    write_u16_be(
        buffer,
        packet->source_port
    );

    write_u16_be(
        buffer + 2,
        packet->destination_port
    );

    write_u16_be(
        buffer + 4,
        (uint16_t)total_len
    );

    write_u16_be(
        buffer + 6,
        packet->checksum
    );

    if (
        packet->payload_len >
        0
    ) {
        memcpy(
            buffer + UDP_HEADER_LEN,
            packet->payload,
            packet->payload_len
        );
    }

    return total_len;
}

uint16_t udp_checksum_ipv4(
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    const uint8_t *udp_data,
    size_t udp_len
)
{
    if (
        source_ip == NULL ||
        destination_ip == NULL ||
        udp_data == NULL ||
        udp_len <
        UDP_HEADER_LEN ||
        udp_len >
        UINT16_MAX
    ) {
        return 0;
    }

    uint32_t sum = 0;

    sum = checksum_add_word(
        sum,
        (uint16_t)(
            ((uint16_t)source_ip[0] << 8) |
            source_ip[1]
        )
    );

    sum = checksum_add_word(
        sum,
        (uint16_t)(
            ((uint16_t)source_ip[2] << 8) |
            source_ip[3]
        )
    );

    sum = checksum_add_word(
        sum,
        (uint16_t)(
            ((uint16_t)destination_ip[0] << 8) |
            destination_ip[1]
        )
    );

    sum = checksum_add_word(
        sum,
        (uint16_t)(
            ((uint16_t)destination_ip[2] << 8) |
            destination_ip[3]
        )
    );

    /*
     * Zero byte + protocol number 17.
     */
    sum = checksum_add_word(
        sum,
        0x0011
    );

    sum = checksum_add_word(
        sum,
        (uint16_t)udp_len
    );

    size_t i = 0;

    while (
        i + 1 <
        udp_len
    ) {
        uint16_t word =
            (uint16_t)(
                ((uint16_t)udp_data[i] << 8) |
                udp_data[i + 1]
            );

        sum =
            checksum_add_word(
                sum,
                word
            );

        i += 2;
    }

    if (i < udp_len) {
        sum =
            checksum_add_word(
                sum,
                (uint16_t)(
                    (uint16_t)udp_data[i] <<
                    8
                )
            );
    }

    uint16_t result =
        checksum_finish(sum);

    if (result == 0) {
        return 0xFFFF;
    }

    return result;
}

size_t udp_serialize_ipv4(
    const udp_packet_t *packet,
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    uint8_t *buffer,
    size_t buffer_len
)
{
    if (
        packet == NULL ||
        source_ip == NULL ||
        destination_ip == NULL ||
        buffer == NULL
    ) {
        return 0;
    }

    udp_packet_t temp =
        *packet;

    temp.checksum = 0;

    size_t udp_len =
        udp_serialize(
            &temp,
            buffer,
            buffer_len
        );

    if (udp_len == 0) {
        return 0;
    }

    uint16_t checksum =
        udp_checksum_ipv4(
            source_ip,
            destination_ip,
            buffer,
            udp_len
        );

    if (checksum == 0) {
        return 0;
    }

    write_u16_be(
        buffer + 6,
        checksum
    );

    return udp_len;
}

int udp_checksum_ipv4_valid(
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    const uint8_t *udp_data,
    size_t udp_len
)
{
    if (
        source_ip == NULL ||
        destination_ip == NULL ||
        udp_data == NULL ||
        udp_len <
        UDP_HEADER_LEN
    ) {
        return 0;
    }

    uint16_t checksum =
        read_u16_be(
            udp_data + 6
        );

    /*
     * UDP checksum is optional over IPv4.
     */
    if (checksum == 0) {
        return 1;
    }

    /*
     * Run the checksum over the complete datagram, including
     * its checksum field. A valid datagram should reduce to zero.
     *
     * udp_checksum_ipv4() maps calculated zero to 0xFFFF for
     * transmission, so verify manually here.
     */

    uint32_t sum = 0;

    sum = checksum_add_word(
        sum,
        (uint16_t)(
            ((uint16_t)source_ip[0] << 8) |
            source_ip[1]
        )
    );

    sum = checksum_add_word(
        sum,
        (uint16_t)(
            ((uint16_t)source_ip[2] << 8) |
            source_ip[3]
        )
    );

    sum = checksum_add_word(
        sum,
        (uint16_t)(
            ((uint16_t)destination_ip[0] << 8) |
            destination_ip[1]
        )
    );

    sum = checksum_add_word(
        sum,
        (uint16_t)(
            ((uint16_t)destination_ip[2] << 8) |
            destination_ip[3]
        )
    );

    sum = checksum_add_word(
        sum,
        0x0011
    );

    sum = checksum_add_word(
        sum,
        (uint16_t)udp_len
    );

    size_t i = 0;

    while (
        i + 1 <
        udp_len
    ) {
        sum =
            checksum_add_word(
                sum,
                (uint16_t)(
                    ((uint16_t)udp_data[i] << 8) |
                    udp_data[i + 1]
                )
            );

        i += 2;
    }

    if (i < udp_len) {
        sum =
            checksum_add_word(
                sum,
                (uint16_t)(
                    (uint16_t)udp_data[i] <<
                    8
                )
            );
    }

    return
        checksum_finish(sum) == 0;
}
