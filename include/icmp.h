#ifndef BLACKTERM_ICMP_H
#define BLACKTERM_ICMP_H

#include <stddef.h>
#include <stdint.h>

#define ICMP_TYPE_ECHO_REPLY   0
#define ICMP_TYPE_ECHO_REQUEST 8

#define ICMP_CODE_ECHO 0

#define ICMP_ECHO_HEADER_LEN 8

#define ICMP_MAX_PACKET_LEN 65535
#define ICMP_MAX_PAYLOAD_LEN \
    (ICMP_MAX_PACKET_LEN - ICMP_ECHO_HEADER_LEN)

typedef struct {
    uint8_t type;
    uint8_t code;

    uint16_t checksum;

    uint16_t identifier;
    uint16_t sequence;

    uint8_t payload[ICMP_MAX_PAYLOAD_LEN];
    size_t payload_len;
} icmp_packet_t;

/*
 * Calculate the standard Internet checksum used by ICMP.
 */
uint16_t icmp_checksum(
    const uint8_t *data,
    size_t data_len
);

/*
 * Build an ICMP Echo Request packet.
 */
int icmp_build_echo_request(
    icmp_packet_t *packet,
    uint16_t identifier,
    uint16_t sequence,
    const uint8_t *payload,
    size_t payload_len
);

/*
 * Build an ICMP Echo Reply packet.
 */
int icmp_build_echo_reply(
    icmp_packet_t *packet,
    uint16_t identifier,
    uint16_t sequence,
    const uint8_t *payload,
    size_t payload_len
);

/*
 * Serialize ICMP packet to wire-format bytes.
 *
 * Checksum is calculated automatically.
 *
 * Returns bytes written, or 0 on failure.
 */
size_t icmp_serialize(
    const icmp_packet_t *packet,
    uint8_t *buffer,
    size_t buffer_len
);

/*
 * Parse an ICMP Echo Request or Echo Reply.
 *
 * Returns:
 *   0  success
 *  -1  invalid argument
 *  -2  packet too short
 *  -3  unsupported type
 *  -4  unsupported code
 *  -5  invalid checksum
 *  -6  payload too large
 */
int icmp_parse(
    const uint8_t *data,
    size_t data_len,
    icmp_packet_t *packet
);

/*
 * Human-readable ICMP type name.
 */
const char *icmp_type_name(uint8_t type);

#endif
