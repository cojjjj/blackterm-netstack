#include "ethernet.h"
#include "ipv4.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_ipv4_inside_ethernet_frame(void)
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

    const uint8_t payload[] = {
        0xDE, 0xAD, 0xBE, 0xEF
    };

    ipv4_packet_t ipv4_packet;

    assert(
        ipv4_build(
            &ipv4_packet,
            source_ip,
            destination_ip,
            IPV4_PROTOCOL_ICMP,
            payload,
            sizeof(payload),
            64,
            0x1234
        ) == 0
    );

    uint8_t ipv4_bytes[IPV4_MAX_PACKET_LEN];

    size_t ipv4_len = ipv4_serialize(
        &ipv4_packet,
        ipv4_bytes,
        sizeof(ipv4_bytes)
    );

    assert(ipv4_len > 0);

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
            parsed_ethernet.destination,
            destination_mac,
            ETHERNET_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            parsed_ethernet.source,
            source_mac,
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

    assert(parsed_ipv4.version == 4);
    assert(parsed_ipv4.protocol == IPV4_PROTOCOL_ICMP);
    assert(parsed_ipv4.ttl == 64);
    assert(parsed_ipv4.identification == 0x1234);

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

    assert(
        parsed_ipv4.payload_len ==
        sizeof(payload)
    );

    assert(
        memcmp(
            parsed_ipv4.payload,
            payload,
            sizeof(payload)
        ) == 0
    );
}

int main(void)
{
    test_ipv4_inside_ethernet_frame();

    printf(
        "[PASS] IPv4 packet embedded in Ethernet\n"
        "[PASS] Ethernet IPv4 EtherType\n"
        "[PASS] Ethernet serialization/parsing\n"
        "[PASS] IPv4 payload recovery\n"
        "[PASS] IPv4 checksum preserved\n"
        "[PASS] Ethernet + IPv4 cross-layer round-trip\n"
        "\n"
        "BLACKTERM // NETSTACK Ethernet + IPv4 integration passed.\n"
    );

    return 0;
}
