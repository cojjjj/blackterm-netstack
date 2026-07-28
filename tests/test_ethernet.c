#include "ethernet.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_parse_ipv4_frame(void)
{
    const uint8_t raw_frame[] = {
        /*
         * Destination MAC
         * AA:BB:CC:DD:EE:FF
         */
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,

        /*
         * Source MAC
         * 11:22:33:44:55:66
         */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,

        /*
         * EtherType
         * IPv4 = 0x0800
         */
        0x08, 0x00,

        /*
         * Dummy payload
         */
        0xDE, 0xAD, 0xBE, 0xEF
    };

    ethernet_frame_t frame;

    int result = ethernet_parse(
        raw_frame,
        sizeof(raw_frame),
        &frame
    );

    assert(result == 0);

    const uint8_t expected_destination[] = {
        0xAA, 0xBB, 0xCC,
        0xDD, 0xEE, 0xFF
    };

    const uint8_t expected_source[] = {
        0x11, 0x22, 0x33,
        0x44, 0x55, 0x66
    };

    assert(
        memcmp(
            frame.destination,
            expected_destination,
            ETHERNET_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            frame.source,
            expected_source,
            ETHERNET_ADDR_LEN
        ) == 0
    );

    assert(frame.ethertype == ETHERNET_TYPE_IPV4);

    assert(frame.payload_len == 4);

    assert(frame.payload[0] == 0xDE);
    assert(frame.payload[1] == 0xAD);
    assert(frame.payload[2] == 0xBE);
    assert(frame.payload[3] == 0xEF);
}

static void test_serialize_round_trip(void)
{
    const uint8_t original[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,

        0x08, 0x06,

        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    ethernet_frame_t frame;

    int parse_result = ethernet_parse(
        original,
        sizeof(original),
        &frame
    );

    assert(parse_result == 0);
    assert(frame.ethertype == ETHERNET_TYPE_ARP);

    uint8_t serialized[ETHERNET_MAX_FRAME_LEN];

    size_t serialized_len = ethernet_serialize(
        &frame,
        serialized,
        sizeof(serialized)
    );

    assert(serialized_len == sizeof(original));

    assert(
        memcmp(
            original,
            serialized,
            sizeof(original)
        ) == 0
    );
}

static void test_mac_formatting(void)
{
    const uint8_t mac[] = {
        0xDE,
        0xAD,
        0xBE,
        0xEF,
        0x12,
        0x34
    };

    char output[18];

    int result = ethernet_mac_to_string(
        mac,
        output,
        sizeof(output)
    );

    assert(result == 0);

    assert(
        strcmp(
            output,
            "DE:AD:BE:EF:12:34"
        ) == 0
    );
}

static void test_reject_short_frame(void)
{
    const uint8_t short_frame[] = {
        0x00,
        0x01,
        0x02
    };

    ethernet_frame_t frame;

    int result = ethernet_parse(
        short_frame,
        sizeof(short_frame),
        &frame
    );

    assert(result == -2);
}

static void test_reject_small_output_buffer(void)
{
    ethernet_frame_t frame = {0};

    frame.ethertype = ETHERNET_TYPE_IPV4;
    frame.payload_len = 10;

    uint8_t buffer[10];

    size_t result = ethernet_serialize(
        &frame,
        buffer,
        sizeof(buffer)
    );

    assert(result == 0);
}

static void test_ethertype_names(void)
{
    assert(
        strcmp(
            ethernet_ethertype_name(ETHERNET_TYPE_IPV4),
            "IPv4"
        ) == 0
    );

    assert(
        strcmp(
            ethernet_ethertype_name(ETHERNET_TYPE_ARP),
            "ARP"
        ) == 0
    );

    assert(
        strcmp(
            ethernet_ethertype_name(ETHERNET_TYPE_IPV6),
            "IPv6"
        ) == 0
    );

    assert(
        strcmp(
            ethernet_ethertype_name(0x1234),
            "Unknown"
        ) == 0
    );
}

int main(void)
{
    test_parse_ipv4_frame();

    test_serialize_round_trip();

    test_mac_formatting();

    test_reject_short_frame();

    test_reject_small_output_buffer();

    test_ethertype_names();

    printf(
        "[PASS] Ethernet parser\n"
        "[PASS] Ethernet serializer\n"
        "[PASS] Ethernet round-trip\n"
        "[PASS] MAC formatting\n"
        "[PASS] Invalid frame handling\n"
        "[PASS] EtherType identification\n"
        "\n"
        "BLACKTERM // NETSTACK Ethernet tests passed.\n"
    );

    return 0;
}
