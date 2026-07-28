#include "arp.h"

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

static int arp_packet_is_valid(const arp_packet_t *packet)
{
    if (packet == NULL) {
        return 0;
    }

    if (packet->hardware_type != ARP_ETHERNET) {
        return 0;
    }

    if (packet->protocol_type != ARP_PROTOCOL_IPV4) {
        return 0;
    }

    if (packet->hardware_addr_len != ARP_HARDWARE_ADDR_LEN) {
        return 0;
    }

    if (packet->protocol_addr_len != ARP_PROTOCOL_ADDR_LEN) {
        return 0;
    }

    if (
        packet->opcode != ARP_OPCODE_REQUEST &&
        packet->opcode != ARP_OPCODE_REPLY
    ) {
        return 0;
    }

    return 1;
}

int arp_parse(
    const uint8_t *data,
    size_t data_len,
    arp_packet_t *packet
)
{
    if (data == NULL || packet == NULL) {
        return -1;
    }

    if (data_len < ARP_PACKET_LEN) {
        return -2;
    }

    uint16_t hardware_type = read_u16_be(data);
    uint16_t protocol_type = read_u16_be(data + 2);

    uint8_t hardware_addr_len = data[4];
    uint8_t protocol_addr_len = data[5];

    uint16_t opcode = read_u16_be(data + 6);

    if (hardware_type != ARP_ETHERNET) {
        return -3;
    }

    if (protocol_type != ARP_PROTOCOL_IPV4) {
        return -4;
    }

    if (
        hardware_addr_len != ARP_HARDWARE_ADDR_LEN ||
        protocol_addr_len != ARP_PROTOCOL_ADDR_LEN
    ) {
        return -5;
    }

    if (
        opcode != ARP_OPCODE_REQUEST &&
        opcode != ARP_OPCODE_REPLY
    ) {
        return -6;
    }

    memset(packet, 0, sizeof(*packet));

    packet->hardware_type = hardware_type;
    packet->protocol_type = protocol_type;

    packet->hardware_addr_len = hardware_addr_len;
    packet->protocol_addr_len = protocol_addr_len;

    packet->opcode = opcode;

    memcpy(
        packet->sender_mac,
        data + 8,
        ARP_HARDWARE_ADDR_LEN
    );

    memcpy(
        packet->sender_ip,
        data + 14,
        ARP_PROTOCOL_ADDR_LEN
    );

    memcpy(
        packet->target_mac,
        data + 18,
        ARP_HARDWARE_ADDR_LEN
    );

    memcpy(
        packet->target_ip,
        data + 24,
        ARP_PROTOCOL_ADDR_LEN
    );

    return 0;
}

size_t arp_serialize(
    const arp_packet_t *packet,
    uint8_t *buffer,
    size_t buffer_len
)
{
    if (packet == NULL || buffer == NULL) {
        return 0;
    }

    if (buffer_len < ARP_PACKET_LEN) {
        return 0;
    }

    if (!arp_packet_is_valid(packet)) {
        return 0;
    }

    write_u16_be(buffer, packet->hardware_type);
    write_u16_be(buffer + 2, packet->protocol_type);

    buffer[4] = packet->hardware_addr_len;
    buffer[5] = packet->protocol_addr_len;

    write_u16_be(buffer + 6, packet->opcode);

    memcpy(
        buffer + 8,
        packet->sender_mac,
        ARP_HARDWARE_ADDR_LEN
    );

    memcpy(
        buffer + 14,
        packet->sender_ip,
        ARP_PROTOCOL_ADDR_LEN
    );

    memcpy(
        buffer + 18,
        packet->target_mac,
        ARP_HARDWARE_ADDR_LEN
    );

    memcpy(
        buffer + 24,
        packet->target_ip,
        ARP_PROTOCOL_ADDR_LEN
    );

    return ARP_PACKET_LEN;
}

int arp_build_request(
    arp_packet_t *packet,
    const uint8_t sender_mac[ARP_HARDWARE_ADDR_LEN],
    const uint8_t sender_ip[ARP_PROTOCOL_ADDR_LEN],
    const uint8_t target_ip[ARP_PROTOCOL_ADDR_LEN]
)
{
    if (
        packet == NULL ||
        sender_mac == NULL ||
        sender_ip == NULL ||
        target_ip == NULL
    ) {
        return -1;
    }

    memset(packet, 0, sizeof(*packet));

    packet->hardware_type = ARP_ETHERNET;
    packet->protocol_type = ARP_PROTOCOL_IPV4;

    packet->hardware_addr_len = ARP_HARDWARE_ADDR_LEN;
    packet->protocol_addr_len = ARP_PROTOCOL_ADDR_LEN;

    packet->opcode = ARP_OPCODE_REQUEST;

    memcpy(
        packet->sender_mac,
        sender_mac,
        ARP_HARDWARE_ADDR_LEN
    );

    memcpy(
        packet->sender_ip,
        sender_ip,
        ARP_PROTOCOL_ADDR_LEN
    );

    /*
     * In an ARP request, the target hardware address is unknown.
     * It is represented as six zero bytes.
     */
    memset(
        packet->target_mac,
        0,
        ARP_HARDWARE_ADDR_LEN
    );

    memcpy(
        packet->target_ip,
        target_ip,
        ARP_PROTOCOL_ADDR_LEN
    );

    return 0;
}

int arp_build_reply(
    arp_packet_t *packet,
    const uint8_t sender_mac[ARP_HARDWARE_ADDR_LEN],
    const uint8_t sender_ip[ARP_PROTOCOL_ADDR_LEN],
    const uint8_t target_mac[ARP_HARDWARE_ADDR_LEN],
    const uint8_t target_ip[ARP_PROTOCOL_ADDR_LEN]
)
{
    if (
        packet == NULL ||
        sender_mac == NULL ||
        sender_ip == NULL ||
        target_mac == NULL ||
        target_ip == NULL
    ) {
        return -1;
    }

    memset(packet, 0, sizeof(*packet));

    packet->hardware_type = ARP_ETHERNET;
    packet->protocol_type = ARP_PROTOCOL_IPV4;

    packet->hardware_addr_len = ARP_HARDWARE_ADDR_LEN;
    packet->protocol_addr_len = ARP_PROTOCOL_ADDR_LEN;

    packet->opcode = ARP_OPCODE_REPLY;

    memcpy(
        packet->sender_mac,
        sender_mac,
        ARP_HARDWARE_ADDR_LEN
    );

    memcpy(
        packet->sender_ip,
        sender_ip,
        ARP_PROTOCOL_ADDR_LEN
    );

    memcpy(
        packet->target_mac,
        target_mac,
        ARP_HARDWARE_ADDR_LEN
    );

    memcpy(
        packet->target_ip,
        target_ip,
        ARP_PROTOCOL_ADDR_LEN
    );

    return 0;
}

int arp_ipv4_to_string(
    const uint8_t ip[ARP_PROTOCOL_ADDR_LEN],
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

const char *arp_opcode_name(uint16_t opcode)
{
    switch (opcode) {
        case ARP_OPCODE_REQUEST:
            return "Request";

        case ARP_OPCODE_REPLY:
            return "Reply";

        default:
            return "Unknown";
    }
}
