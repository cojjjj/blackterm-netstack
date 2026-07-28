#ifndef BLACKTERM_IPV4_H
#define BLACKTERM_IPV4_H

#include <stddef.h>
#include <stdint.h>

#define IPV4_ADDR_LEN 4

#define IPV4_VERSION 4

#define IPV4_MIN_IHL 5
#define IPV4_MIN_HEADER_LEN 20
#define IPV4_MAX_HEADER_LEN 60

#define IPV4_MAX_PACKET_LEN 65535
#define IPV4_MAX_PAYLOAD_LEN \
    (IPV4_MAX_PACKET_LEN - IPV4_MIN_HEADER_LEN)

/* Common IP protocol numbers. */
#define IPV4_PROTOCOL_ICMP 1
#define IPV4_PROTOCOL_TCP  6
#define IPV4_PROTOCOL_UDP  17

/* Fragmentation flags stored in the 3-bit flags field. */
#define IPV4_FLAG_RESERVED 0x04
#define IPV4_FLAG_DF       0x02
#define IPV4_FLAG_MF       0x01

typedef struct {
    uint8_t version;
    uint8_t ihl;

    uint8_t dscp;
    uint8_t ecn;

    uint16_t total_length;
    uint16_t identification;

    uint8_t flags;
    uint16_t fragment_offset;

    uint8_t ttl;
    uint8_t protocol;

    uint16_t header_checksum;

    uint8_t source_ip[IPV4_ADDR_LEN];
    uint8_t destination_ip[IPV4_ADDR_LEN];

    uint8_t options[IPV4_MAX_HEADER_LEN - IPV4_MIN_HEADER_LEN];
    size_t options_len;

    uint8_t payload[IPV4_MAX_PAYLOAD_LEN];
    size_t payload_len;
} ipv4_packet_t;

/*
 * Calculate the IPv4 Internet checksum over a buffer.
 *
 * The checksum field should contain zero when calculating
 * a checksum for a newly constructed header.
 */
uint16_t ipv4_checksum(
    const uint8_t *data,
    size_t data_len
);

/*
 * Parse raw IPv4 bytes.
 *
 * Returns:
 *   0   success
 *  -1   invalid argument
 *  -2   packet too short
 *  -3   unsupported version
 *  -4   invalid IHL
 *  -5   invalid total length
 *  -6   invalid header checksum
 *  -7   payload too large
 */
int ipv4_parse(
    const uint8_t *data,
    size_t data_len,
    ipv4_packet_t *packet
);

/*
 * Serialize an IPv4 packet.
 *
 * The header checksum is calculated automatically.
 *
 * Returns number of bytes written on success.
 * Returns 0 on failure.
 */
size_t ipv4_serialize(
    const ipv4_packet_t *packet,
    uint8_t *buffer,
    size_t buffer_len
);

/*
 * Construct a basic IPv4 packet with no options.
 */
int ipv4_build(
    ipv4_packet_t *packet,
    const uint8_t source_ip[IPV4_ADDR_LEN],
    const uint8_t destination_ip[IPV4_ADDR_LEN],
    uint8_t protocol,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t ttl,
    uint16_t identification
);

/*
 * Convert an IPv4 address to dotted-decimal notation.
 *
 * Buffer must be at least 16 bytes.
 */
int ipv4_address_to_string(
    const uint8_t ip[IPV4_ADDR_LEN],
    char *buffer,
    size_t buffer_len
);

/*
 * Human-readable protocol name.
 */
const char *ipv4_protocol_name(uint8_t protocol);

#endif
