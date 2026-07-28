#ifndef BLACKTERM_ETHERNET_H
#define BLACKTERM_ETHERNET_H

#include <stddef.h>
#include <stdint.h>

#define ETHERNET_ADDR_LEN 6
#define ETHERNET_HEADER_LEN 14
#define ETHERNET_MAX_PAYLOAD 1500
#define ETHERNET_MAX_FRAME_LEN \
    (ETHERNET_HEADER_LEN + ETHERNET_MAX_PAYLOAD)

#define ETHERNET_TYPE_IPV4 0x0800
#define ETHERNET_TYPE_ARP  0x0806
#define ETHERNET_TYPE_IPV6 0x86DD

typedef struct {
    uint8_t destination[ETHERNET_ADDR_LEN];
    uint8_t source[ETHERNET_ADDR_LEN];

    uint16_t ethertype;

    uint8_t payload[ETHERNET_MAX_PAYLOAD];
    size_t payload_len;
} ethernet_frame_t;

/*
 * Parse raw Ethernet frame bytes into ethernet_frame_t.
 *
 * Returns:
 *   0  success
 *  -1  invalid argument
 *  -2  frame too short
 *  -3  payload too large
 */
int ethernet_parse(
    const uint8_t *data,
    size_t data_len,
    ethernet_frame_t *frame
);

/*
 * Serialize ethernet_frame_t into raw bytes.
 *
 * Returns number of bytes written on success.
 * Returns 0 on failure.
 */
size_t ethernet_serialize(
    const ethernet_frame_t *frame,
    uint8_t *buffer,
    size_t buffer_len
);

/*
 * Convert a MAC address into:
 *
 * AA:BB:CC:DD:EE:FF
 *
 * The output buffer must be at least 18 bytes.
 */
int ethernet_mac_to_string(
    const uint8_t mac[ETHERNET_ADDR_LEN],
    char *buffer,
    size_t buffer_len
);

/*
 * Returns a human-readable name for known EtherTypes.
 */
const char *ethernet_ethertype_name(uint16_t ethertype);

#endif
