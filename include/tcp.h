#ifndef BLACKTERM_TCP_H
#define BLACKTERM_TCP_H

#include <stddef.h>
#include <stdint.h>

#define TCP_MIN_HEADER_LEN 20
#define TCP_MAX_HEADER_LEN 60
#define TCP_MAX_PACKET_LEN 65535
#define TCP_MAX_PAYLOAD_LEN \
    (TCP_MAX_PACKET_LEN - TCP_MIN_HEADER_LEN)

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;

    uint32_t sequence_number;
    uint32_t acknowledgment_number;

    uint8_t data_offset;
    uint8_t flags;

    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    uint8_t options[
        TCP_MAX_HEADER_LEN -
        TCP_MIN_HEADER_LEN
    ];

    size_t options_len;

    uint8_t payload[TCP_MAX_PAYLOAD_LEN];
    size_t payload_len;
} tcp_segment_t;

/*
 * Build a basic TCP segment without options.
 */
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
);

/*
 * Parse a TCP segment.
 *
 * Returns:
 *   0 success
 *  -1 invalid arguments
 *  -2 segment too short
 *  -3 invalid data offset
 *  -4 payload too large
 */
int tcp_parse(
    const uint8_t *data,
    size_t data_len,
    tcp_segment_t *segment
);

/*
 * Serialize a TCP segment without calculating
 * the IPv4 pseudo-header checksum.
 */
size_t tcp_serialize(
    const tcp_segment_t *segment,
    uint8_t *buffer,
    size_t buffer_len
);

/*
 * Calculate TCP checksum using the IPv4 pseudo-header.
 */
uint16_t tcp_checksum_ipv4(
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    const uint8_t *tcp_data,
    size_t tcp_len
);

/*
 * Serialize and automatically calculate the TCP checksum.
 */
size_t tcp_serialize_ipv4(
    const tcp_segment_t *segment,
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    uint8_t *buffer,
    size_t buffer_len
);

/*
 * Verify the checksum of a received TCP segment.
 *
 * Returns:
 *   1 valid
 *   0 invalid
 */
int tcp_checksum_ipv4_valid(
    const uint8_t source_ip[4],
    const uint8_t destination_ip[4],
    const uint8_t *tcp_data,
    size_t tcp_len
);

const char *tcp_state_flag_name(
    uint8_t flags
);

#endif
