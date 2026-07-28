#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_icmp_echo_request_full_stack(void)
{
    const uint8_t source_mac[] = {
        0xDE, 0xAD, 0xBE,
        0xEF, 0x12, 0x34
    };

    const uint8_t destination_mac[] = {
        0xAA, 0xBB, 0xCC,
        0xDD, 0xEE, 0xFF
    };

    const uint8_t source_ip[] = {
        192, 168, 1, 50
    };

    const uint8_t destination_ip[] = {
        192, 168, 1, 1
    };

    const uint8_t ping_payload[] = {
        'B', 'L', 'A', 'C', 'K',
        'T', 'E', 'R', 'M'
    };

    /*
     * Layer 4-ish control protocol:
     * Build ICMP Echo Request.
     */
    icmp_packet_t icmp_packet;

    assert(
        icmp_build_echo_request(
            &icmp_packet,
            0x1234,
            1,
            ping_payload,
            sizeof(ping_payload)
        ) == 0
    );

    uint8_t icmp_bytes[ICMP_MAX_PACKET_LEN];

    size_t icmp_len = icmp_serialize(
        &icmp_packet,
        icmp_bytes,
        sizeof(icmp_bytes)
    );

    assert(
        icmp_len ==
        ICMP_ECHO_HEADER_LEN + sizeof(ping_payload)
    );

    assert(
        icmp_checksum(
            icmp_bytes,
            icmp_len
        ) == 0
    );

    /*
     * Layer 3:
     * Put ICMP inside IPv4.
     */
    ipv4_packet_t ipv4_packet;

    assert(
        ipv4_build(
            &ipv4_packet,
            source_ip,
            destination_ip,
            IPV4_PROTOCOL_ICMP,
            icmp_bytes,
            icmp_len,
            64,
            0x4242
        ) == 0
    );

    uint8_t ipv4_bytes[IPV4_MAX_PACKET_LEN];

    size_t ipv4_len = ipv4_serialize(
        &ipv4_packet,
        ipv4_bytes,
        sizeof(ipv4_bytes)
    );

    assert(ipv4_len > 0);

    assert(
        ipv4_checksum(
            ipv4_bytes,
            IPV4_MIN_HEADER_LEN
        ) == 0
    );

    /*
     * Layer 2:
     * Put IPv4 inside Ethernet.
     */
    ethernet_frame_t ethernet_frame = {0};

    memcpy(
        ethernet_frame.destination,
        destination_mac,
        ETHERNET_ADDR_LEN
    );

    memcpy(
        ethernet_frame.source,
        source_mac,
        ETHERNET_ADDR_LEN
    );

    ethernet_frame.ethertype = ETHERNET_TYPE_IPV4;

    memcpy(
        ethernet_frame.payload,
        ipv4_bytes,
        ipv4_len
    );

    ethernet_frame.payload_len = ipv4_len;

    uint8_t ethernet_bytes[ETHERNET_MAX_FRAME_LEN];

    size_t ethernet_len = ethernet_serialize(
        &ethernet_frame,
        ethernet_bytes,
        sizeof(ethernet_bytes)
    );

    assert(
        ethernet_len ==
        ETHERNET_HEADER_LEN + ipv4_len
    );

    /*
     * Now walk the packet backward:
     *
     * Ethernet -> IPv4 -> ICMP
     */

    ethernet_frame_t parsed_ethernet;

    assert(
        ethernet_parse(
            ethernet_bytes,
            ethernet_len,
            &parsed_ethernet
        ) == 0
    );

    assert(
        parsed_ethernet.ethertype ==
        ETHERNET_TYPE_IPV4
    );

    assert(
        memcmp(
            parsed_ethernet.source,
            source_mac,
            ETHERNET_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            parsed_ethernet.destination,
            destination_mac,
            ETHERNET_ADDR_LEN
        ) == 0
    );

    ipv4_packet_t parsed_ipv4;

    assert(
        ipv4_parse(
            parsed_ethernet.payload,
            parsed_ethernet.payload_len,
            &parsed_ipv4
        ) == 0
    );

    assert(
        parsed_ipv4.protocol ==
        IPV4_PROTOCOL_ICMP
    );

    assert(parsed_ipv4.ttl == 64);
    assert(parsed_ipv4.identification == 0x4242);

    assert(
        memcmp(
            parsed_ipv4.source_ip,
            source_ip,
            IPV4_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            parsed_ipv4.destination_ip,
            destination_ip,
            IPV4_ADDR_LEN
        ) == 0
    );

    icmp_packet_t parsed_icmp;

    assert(
        icmp_parse(
            parsed_ipv4.payload,
            parsed_ipv4.payload_len,
            &parsed_icmp
        ) == 0
    );

    assert(
        parsed_icmp.type ==
        ICMP_TYPE_ECHO_REQUEST
    );

    assert(
        parsed_icmp.code ==
        ICMP_CODE_ECHO
    );

    assert(parsed_icmp.identifier == 0x1234);
    assert(parsed_icmp.sequence == 1);

    assert(
        parsed_icmp.payload_len ==
        sizeof(ping_payload)
    );

    assert(
        memcmp(
            parsed_icmp.payload,
            ping_payload,
            sizeof(ping_payload)
        ) == 0
    );
}

int main(void)
{
    test_icmp_echo_request_full_stack();

    printf(
        "[PASS] ICMP Echo Request construction\n"
        "[PASS] ICMP checksum\n"
        "[PASS] ICMP embedded in IPv4\n"
        "[PASS] IPv4 checksum\n"
        "[PASS] IPv4 embedded in Ethernet\n"
        "[PASS] Ethernet serialization/parsing\n"
        "[PASS] IPv4 recovery/parsing\n"
        "[PASS] ICMP recovery/parsing\n"
        "[PASS] Full-stack round-trip\n"
        "\n"
        "BLACKTERM // NETSTACK Ethernet + IPv4 + ICMP integration passed.\n"
    );

    return 0;
}
