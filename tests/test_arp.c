#include "arp.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_parse_request(void)
{
    const uint8_t raw_arp[] = {
        /*
         * Hardware type: Ethernet
         */
        0x00, 0x01,

        /*
         * Protocol type: IPv4
         */
        0x08, 0x00,

        /*
         * Hardware/protocol address lengths
         */
        0x06,
        0x04,

        /*
         * Opcode: Request
         */
        0x00, 0x01,

        /*
         * Sender MAC
         * 00:11:22:33:44:55
         */
        0x00, 0x11, 0x22,
        0x33, 0x44, 0x55,

        /*
         * Sender IP
         * 192.168.1.50
         */
        0xC0, 0xA8, 0x01, 0x32,

        /*
         * Target MAC unknown
         */
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,

        /*
         * Target IP
         * 192.168.1.1
         */
        0xC0, 0xA8, 0x01, 0x01
    };

    arp_packet_t packet;

    int result = arp_parse(
        raw_arp,
        sizeof(raw_arp),
        &packet
    );

    assert(result == 0);

    assert(packet.hardware_type == ARP_ETHERNET);
    assert(packet.protocol_type == ARP_PROTOCOL_IPV4);

    assert(packet.hardware_addr_len == 6);
    assert(packet.protocol_addr_len == 4);

    assert(packet.opcode == ARP_OPCODE_REQUEST);

    const uint8_t expected_sender_mac[] = {
        0x00, 0x11, 0x22,
        0x33, 0x44, 0x55
    };

    assert(
        memcmp(
            packet.sender_mac,
            expected_sender_mac,
            ARP_HARDWARE_ADDR_LEN
        ) == 0
    );

    const uint8_t expected_sender_ip[] = {
        192, 168, 1, 50
    };

    assert(
        memcmp(
            packet.sender_ip,
            expected_sender_ip,
            ARP_PROTOCOL_ADDR_LEN
        ) == 0
    );

    const uint8_t expected_target_ip[] = {
        192, 168, 1, 1
    };

    assert(
        memcmp(
            packet.target_ip,
            expected_target_ip,
            ARP_PROTOCOL_ADDR_LEN
        ) == 0
    );
}

static void test_build_request(void)
{
    const uint8_t sender_mac[] = {
        0xDE, 0xAD, 0xBE,
        0xEF, 0x12, 0x34
    };

    const uint8_t sender_ip[] = {
        192, 168, 50, 10
    };

    const uint8_t target_ip[] = {
        192, 168, 50, 1
    };

    arp_packet_t packet;

    int result = arp_build_request(
        &packet,
        sender_mac,
        sender_ip,
        target_ip
    );

    assert(result == 0);

    assert(packet.hardware_type == ARP_ETHERNET);
    assert(packet.protocol_type == ARP_PROTOCOL_IPV4);

    assert(packet.hardware_addr_len == 6);
    assert(packet.protocol_addr_len == 4);

    assert(packet.opcode == ARP_OPCODE_REQUEST);

    assert(
        memcmp(
            packet.sender_mac,
            sender_mac,
            ARP_HARDWARE_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            packet.sender_ip,
            sender_ip,
            ARP_PROTOCOL_ADDR_LEN
        ) == 0
    );

    const uint8_t zero_mac[] = {
        0, 0, 0, 0, 0, 0
    };

    assert(
        memcmp(
            packet.target_mac,
            zero_mac,
            ARP_HARDWARE_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            packet.target_ip,
            target_ip,
            ARP_PROTOCOL_ADDR_LEN
        ) == 0
    );
}

static void test_build_reply(void)
{
    const uint8_t sender_mac[] = {
        0xAA, 0xBB, 0xCC,
        0xDD, 0xEE, 0xFF
    };

    const uint8_t sender_ip[] = {
        10, 0, 0, 1
    };

    const uint8_t target_mac[] = {
        0x11, 0x22, 0x33,
        0x44, 0x55, 0x66
    };

    const uint8_t target_ip[] = {
        10, 0, 0, 20
    };

    arp_packet_t packet;

    int result = arp_build_reply(
        &packet,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip
    );

    assert(result == 0);
    assert(packet.opcode == ARP_OPCODE_REPLY);

    assert(
        memcmp(
            packet.sender_mac,
            sender_mac,
            ARP_HARDWARE_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            packet.target_mac,
            target_mac,
            ARP_HARDWARE_ADDR_LEN
        ) == 0
    );
}

static void test_round_trip(void)
{
    const uint8_t sender_mac[] = {
        0x02, 0x00, 0x00,
        0x00, 0x00, 0x01
    };

    const uint8_t sender_ip[] = {
        172, 16, 0, 10
    };

    const uint8_t target_ip[] = {
        172, 16, 0, 1
    };

    arp_packet_t original;

    assert(
        arp_build_request(
            &original,
            sender_mac,
            sender_ip,
            target_ip
        ) == 0
    );

    uint8_t serialized[ARP_PACKET_LEN];

    size_t serialized_len = arp_serialize(
        &original,
        serialized,
        sizeof(serialized)
    );

    assert(serialized_len == ARP_PACKET_LEN);

    arp_packet_t parsed;

    assert(
        arp_parse(
            serialized,
            serialized_len,
            &parsed
        ) == 0
    );

    assert(
        memcmp(
            &original,
            &parsed,
            sizeof(original)
        ) == 0
    );
}

static void test_known_wire_format(void)
{
    const uint8_t sender_mac[] = {
        0x00, 0x11, 0x22,
        0x33, 0x44, 0x55
    };

    const uint8_t sender_ip[] = {
        192, 168, 1, 50
    };

    const uint8_t target_ip[] = {
        192, 168, 1, 1
    };

    arp_packet_t packet;

    assert(
        arp_build_request(
            &packet,
            sender_mac,
            sender_ip,
            target_ip
        ) == 0
    );

    uint8_t serialized[ARP_PACKET_LEN];

    assert(
        arp_serialize(
            &packet,
            serialized,
            sizeof(serialized)
        ) == ARP_PACKET_LEN
    );

    const uint8_t expected[] = {
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        0x00, 0x01,

        0x00, 0x11, 0x22,
        0x33, 0x44, 0x55,

        0xC0, 0xA8, 0x01, 0x32,

        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,

        0xC0, 0xA8, 0x01, 0x01
    };

    assert(
        memcmp(
            serialized,
            expected,
            sizeof(expected)
        ) == 0
    );
}

static void test_ipv4_formatting(void)
{
    const uint8_t ip[] = {
        192, 168, 1, 117
    };

    char output[16];

    assert(
        arp_ipv4_to_string(
            ip,
            output,
            sizeof(output)
        ) == 0
    );

    assert(
        strcmp(
            output,
            "192.168.1.117"
        ) == 0
    );
}

static void test_opcode_names(void)
{
    assert(
        strcmp(
            arp_opcode_name(ARP_OPCODE_REQUEST),
            "Request"
        ) == 0
    );

    assert(
        strcmp(
            arp_opcode_name(ARP_OPCODE_REPLY),
            "Reply"
        ) == 0
    );

    assert(
        strcmp(
            arp_opcode_name(0x9999),
            "Unknown"
        ) == 0
    );
}

static void test_reject_short_packet(void)
{
    const uint8_t short_packet[] = {
        0x00,
        0x01,
        0x08,
        0x00
    };

    arp_packet_t packet;

    int result = arp_parse(
        short_packet,
        sizeof(short_packet),
        &packet
    );

    assert(result == -2);
}

static void test_reject_invalid_hardware_type(void)
{
    uint8_t packet_data[ARP_PACKET_LEN] = {
        0x00, 0x99,
        0x08, 0x00,
        0x06,
        0x04,
        0x00, 0x01
    };

    arp_packet_t packet;

    assert(
        arp_parse(
            packet_data,
            sizeof(packet_data),
            &packet
        ) == -3
    );
}

static void test_reject_invalid_protocol_type(void)
{
    uint8_t packet_data[ARP_PACKET_LEN] = {
        0x00, 0x01,
        0x86, 0xDD,
        0x06,
        0x04,
        0x00, 0x01
    };

    arp_packet_t packet;

    assert(
        arp_parse(
            packet_data,
            sizeof(packet_data),
            &packet
        ) == -4
    );
}

static void test_reject_invalid_address_lengths(void)
{
    uint8_t packet_data[ARP_PACKET_LEN] = {
        0x00, 0x01,
        0x08, 0x00,
        0x05,
        0x04,
        0x00, 0x01
    };

    arp_packet_t packet;

    assert(
        arp_parse(
            packet_data,
            sizeof(packet_data),
            &packet
        ) == -5
    );
}

static void test_reject_invalid_opcode(void)
{
    uint8_t packet_data[ARP_PACKET_LEN] = {
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        0x00, 0x99
    };

    arp_packet_t packet;

    assert(
        arp_parse(
            packet_data,
            sizeof(packet_data),
            &packet
        ) == -6
    );
}

static void test_reject_small_serialize_buffer(void)
{
    const uint8_t sender_mac[] = {
        0xDE, 0xAD, 0xBE,
        0xEF, 0x00, 0x01
    };

    const uint8_t sender_ip[] = {
        192, 168, 1, 10
    };

    const uint8_t target_ip[] = {
        192, 168, 1, 1
    };

    arp_packet_t packet;

    assert(
        arp_build_request(
            &packet,
            sender_mac,
            sender_ip,
            target_ip
        ) == 0
    );

    uint8_t output[10];

    assert(
        arp_serialize(
            &packet,
            output,
            sizeof(output)
        ) == 0
    );
}

int main(void)
{
    test_parse_request();
    test_build_request();
    test_build_reply();
    test_round_trip();
    test_known_wire_format();

    test_ipv4_formatting();
    test_opcode_names();

    test_reject_short_packet();
    test_reject_invalid_hardware_type();
    test_reject_invalid_protocol_type();
    test_reject_invalid_address_lengths();
    test_reject_invalid_opcode();
    test_reject_small_serialize_buffer();

    printf(
        "[PASS] ARP request parsing\n"
        "[PASS] ARP request construction\n"
        "[PASS] ARP reply construction\n"
        "[PASS] ARP serialization\n"
        "[PASS] ARP round-trip\n"
        "[PASS] ARP wire-format validation\n"
        "[PASS] IPv4 formatting\n"
        "[PASS] ARP opcode identification\n"
        "[PASS] Malformed ARP rejection\n"
        "\n"
        "BLACKTERM // NETSTACK ARP tests passed.\n"
    );

    return 0;
}
