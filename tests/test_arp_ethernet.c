#include "arp.h"
#include "ethernet.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_arp_request_inside_ethernet_frame(void)
{
    const uint8_t sender_mac[] = {
        0xDE, 0xAD, 0xBE,
        0xEF, 0x12, 0x34
    };

    const uint8_t sender_ip[] = {
        192, 168, 1, 50
    };

    const uint8_t target_ip[] = {
        192, 168, 1, 1
    };

    arp_packet_t arp_packet;

    assert(
        arp_build_request(
            &arp_packet,
            sender_mac,
            sender_ip,
            target_ip
        ) == 0
    );

    uint8_t arp_bytes[ARP_PACKET_LEN];

    size_t arp_len = arp_serialize(
        &arp_packet,
        arp_bytes,
        sizeof(arp_bytes)
    );

    assert(arp_len == ARP_PACKET_LEN);

    ethernet_frame_t frame = {0};

    const uint8_t broadcast_mac[] = {
        0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF
    };

    memcpy(
        frame.destination,
        broadcast_mac,
        ETHERNET_ADDR_LEN
    );

    memcpy(
        frame.source,
        sender_mac,
        ETHERNET_ADDR_LEN
    );

    frame.ethertype = ETHERNET_TYPE_ARP;

    memcpy(
        frame.payload,
        arp_bytes,
        arp_len
    );

    frame.payload_len = arp_len;

    uint8_t ethernet_bytes[ETHERNET_MAX_FRAME_LEN];

    size_t ethernet_len = ethernet_serialize(
        &frame,
        ethernet_bytes,
        sizeof(ethernet_bytes)
    );

    assert(
        ethernet_len ==
        ETHERNET_HEADER_LEN + ARP_PACKET_LEN
    );

    ethernet_frame_t parsed_frame;

    assert(
        ethernet_parse(
            ethernet_bytes,
            ethernet_len,
            &parsed_frame
        ) == 0
    );

    assert(
        memcmp(
            parsed_frame.destination,
            broadcast_mac,
            ETHERNET_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            parsed_frame.source,
            sender_mac,
            ETHERNET_ADDR_LEN
        ) == 0
    );

    assert(
        parsed_frame.ethertype ==
        ETHERNET_TYPE_ARP
    );

    assert(
        parsed_frame.payload_len ==
        ARP_PACKET_LEN
    );

    arp_packet_t parsed_arp;

    assert(
        arp_parse(
            parsed_frame.payload,
            parsed_frame.payload_len,
            &parsed_arp
        ) == 0
    );

    assert(
        parsed_arp.opcode ==
        ARP_OPCODE_REQUEST
    );

    assert(
        memcmp(
            parsed_arp.sender_mac,
            sender_mac,
            ARP_HARDWARE_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            parsed_arp.sender_ip,
            sender_ip,
            ARP_PROTOCOL_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            parsed_arp.target_ip,
            target_ip,
            ARP_PROTOCOL_ADDR_LEN
        ) == 0
    );
}

int main(void)
{
    test_arp_request_inside_ethernet_frame();

    printf(
        "[PASS] ARP request embedded in Ethernet\n"
        "[PASS] Ethernet serialization\n"
        "[PASS] Ethernet parsing\n"
        "[PASS] ARP payload recovery\n"
        "[PASS] Cross-layer round-trip\n"
        "\n"
        "BLACKTERM // NETSTACK Ethernet + ARP integration passed.\n"
    );

    return 0;
}
