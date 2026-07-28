#ifndef BLACKTERM_ARP_H
#define BLACKTERM_ARP_H

#include <stddef.h>
#include <stdint.h>

#define ARP_ETHERNET 0x0001

#define ARP_PROTOCOL_IPV4 0x0800

#define ARP_OPCODE_REQUEST 0x0001
#define ARP_OPCODE_REPLY   0x0002

#define ARP_HARDWARE_ADDR_LEN 6
#define ARP_PROTOCOL_ADDR_LEN 4

/*
 * Standard Ethernet/IPv4 ARP packet:
 *
 * 2 bytes hardware type
 * 2 bytes protocol type
 * 1 byte  hardware address length
 * 1 byte  protocol address length
 * 2 bytes opcode
 * 6 bytes sender MAC
 * 4 bytes sender IPv4
 * 6 bytes target MAC
 * 4 bytes target IPv4
 *
 * Total: 28 bytes
 */
#define ARP_PACKET_LEN 28

typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;

    uint8_t hardware_addr_len;
    uint8_t protocol_addr_len;

    uint16_t opcode;

    uint8_t sender_mac[ARP_HARDWARE_ADDR_LEN];
    uint8_t sender_ip[ARP_PROTOCOL_ADDR_LEN];

    uint8_t target_mac[ARP_HARDWARE_ADDR_LEN];
    uint8_t target_ip[ARP_PROTOCOL_ADDR_LEN];
} arp_packet_t;

/*
 * Parse a raw Ethernet/IPv4 ARP packet.
 *
 * Returns:
 *   0  success
 *  -1  invalid argument
 *  -2  packet too short
 *  -3  unsupported hardware type
 *  -4  unsupported protocol type
 *  -5  invalid address lengths
 *  -6  unsupported opcode
 */
int arp_parse(
    const uint8_t *data,
    size_t data_len,
    arp_packet_t *packet
);

/*
 * Serialize an ARP packet into the 28-byte wire format.
 *
 * Returns number of bytes written on success.
 * Returns 0 on failure.
 */
size_t arp_serialize(
    const arp_packet_t *packet,
    uint8_t *buffer,
    size_t buffer_len
);

/*
 * Construct a standard Ethernet/IPv4 ARP request.
 */
int arp_build_request(
    arp_packet_t *packet,
    const uint8_t sender_mac[ARP_HARDWARE_ADDR_LEN],
    const uint8_t sender_ip[ARP_PROTOCOL_ADDR_LEN],
    const uint8_t target_ip[ARP_PROTOCOL_ADDR_LEN]
);

/*
 * Construct a standard Ethernet/IPv4 ARP reply.
 */
int arp_build_reply(
    arp_packet_t *packet,
    const uint8_t sender_mac[ARP_HARDWARE_ADDR_LEN],
    const uint8_t sender_ip[ARP_PROTOCOL_ADDR_LEN],
    const uint8_t target_mac[ARP_HARDWARE_ADDR_LEN],
    const uint8_t target_ip[ARP_PROTOCOL_ADDR_LEN]
);

/*
 * Format an IPv4 address as:
 *
 * 192.168.1.1
 *
 * Buffer must be at least 16 bytes.
 */
int arp_ipv4_to_string(
    const uint8_t ip[ARP_PROTOCOL_ADDR_LEN],
    char *buffer,
    size_t buffer_len
);

/*
 * Return a human-readable ARP opcode name.
 */
const char *arp_opcode_name(uint16_t opcode);

#endif
