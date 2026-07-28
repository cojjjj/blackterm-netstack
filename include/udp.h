#ifndef BLACKTERM_UDP_H
#define BLACKTERM_UDP_H

#include <stddef.h>
#include <stdint.h>

#define UDP_HEADER_LEN 8
#define UDP_MAX_PACKET_LEN 65535
#define UDP_MAX_PAYLOAD_LEN (UDP_MAX_PACKET_LEN - UDP_HEADER_LEN)

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;

    uint8_t payload[UDP_MAX_PAYLOAD_LEN];
    size_t payload_len;
} udp_packet_t;

/*
 * Build a UDP packet.
 */
int udp_build(
    udp_packet_t *packet,
    uint16_t source_port,
    uint16_t destination_port,
    const uint8_t *payload,
    size_t payload_len
);

/*
 * Parse a UDP datagram.
 *
 * Returns:
 *   0  success
 *  -1  invalid arguments
 *  -2  packet too short
 *  -3  invalid UDP length
 *  -4  payload too large
 */
int udp_parse(
    const uint8_t *data,
    size_t data_len,
    udp_packet_t *packet
);

/*
 * Serialize UDP without calculating an IPv4 pseudo-header checksum.
 *
 * The checksum field from packet is written as-is.
 */
size_t udp_serialize(
    const udp_packet_t *packet,
    uint8_t *buffer,
    size_t buffer_len
);

/*
 * Calculate UDP checksum using the IPv4 pseudo-header.
 *
 * source_ip and destination_ip are 4-byte IPv4 addresses.
 *
 * A return value of zero is converted to 0xFFFF for transmission,
 * since a UDP checksum field of zero means "checksum disabled" in IPv4.
 */
uint16_t udp_checksum_ipv4(
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    const uint8_t *udp_data,
    size_t udp_len
);

/*
 * Serialize UDP and calculate/write its IPv4 pseudo-header checksum.
 */
size_t udp_serialize_ipv4(
    const udp_packet_t *packet,
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    uint8_t *buffer,
    size_t buffer_len
);

/*
 * Validate a received UDP checksum.
 *
 * Returns:
 *   1 valid
 *   0 invalid
 *
 * An IPv4 UDP checksum field of zero is treated as valid because
 * checksum use is optional for UDP over IPv4.
 */
int udp_checksum_ipv4_valid(
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    const uint8_t *udp_data,
    size_t udp_len
);

#endif
