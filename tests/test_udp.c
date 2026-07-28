#include "udp.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_build(void)
{
    const uint8_t payload[] = {
        'B', 'L', 'A', 'C', 'K',
        'T', 'E', 'R', 'M'
    };

    udp_packet_t packet;

    assert(
        udp_build(
            &packet,
            50000,
            53,
            payload,
            sizeof(payload)
        ) == 0
    );

    assert(
        packet.source_port ==
        50000
    );

    assert(
        packet.destination_port ==
        53
    );

    assert(
        packet.length ==
        UDP_HEADER_LEN +
        sizeof(payload)
    );

    assert(
        packet.payload_len ==
        sizeof(payload)
    );

    assert(
        memcmp(
            packet.payload,
            payload,
            sizeof(payload)
        ) == 0
    );
}

static void test_basic_serialization(void)
{
    const uint8_t payload[] = {
        0xDE,
        0xAD,
        0xBE,
        0xEF
    };

    udp_packet_t packet;

    assert(
        udp_build(
            &packet,
            0x1234,
            0x0035,
            payload,
            sizeof(payload)
        ) == 0
    );

    uint8_t buffer[32];

    size_t len =
        udp_serialize(
            &packet,
            buffer,
            sizeof(buffer)
        );

    assert(len == 12);

    assert(buffer[0] == 0x12);
    assert(buffer[1] == 0x34);

    assert(buffer[2] == 0x00);
    assert(buffer[3] == 0x35);

    assert(buffer[4] == 0x00);
    assert(buffer[5] == 0x0C);

    /*
     * No checksum in basic serializer.
     */
    assert(buffer[6] == 0x00);
    assert(buffer[7] == 0x00);

    assert(
        memcmp(
            buffer + UDP_HEADER_LEN,
            payload,
            sizeof(payload)
        ) == 0
    );
}

static void test_round_trip(void)
{
    const uint8_t payload[] = {
        1, 2, 3, 4, 5, 6
    };

    udp_packet_t original;

    assert(
        udp_build(
            &original,
            40000,
            9000,
            payload,
            sizeof(payload)
        ) == 0
    );

    uint8_t buffer[64];

    size_t len =
        udp_serialize(
            &original,
            buffer,
            sizeof(buffer)
        );

    assert(
        len ==
        UDP_HEADER_LEN +
        sizeof(payload)
    );

    udp_packet_t parsed;

    assert(
        udp_parse(
            buffer,
            len,
            &parsed
        ) == 0
    );

    assert(
        parsed.source_port ==
        original.source_port
    );

    assert(
        parsed.destination_port ==
        original.destination_port
    );

    assert(
        parsed.length ==
        len
    );

    assert(
        parsed.payload_len ==
        original.payload_len
    );

    assert(
        memcmp(
            parsed.payload,
            original.payload,
            original.payload_len
        ) == 0
    );
}

static void test_ipv4_checksum(void)
{
    const uint8_t source_ip[] = {
        192, 168, 50, 62
    };

    const uint8_t destination_ip[] = {
        8, 8, 8, 8
    };

    const uint8_t payload[] = {
        'D', 'N', 'S'
    };

    udp_packet_t packet;

    assert(
        udp_build(
            &packet,
            50000,
            53,
            payload,
            sizeof(payload)
        ) == 0
    );

    uint8_t buffer[64];

    size_t len =
        udp_serialize_ipv4(
            &packet,
            source_ip,
            destination_ip,
            buffer,
            sizeof(buffer)
        );

    assert(len > 0);

    assert(
        buffer[6] != 0 ||
        buffer[7] != 0
    );

    assert(
        udp_checksum_ipv4_valid(
            source_ip,
            destination_ip,
            buffer,
            len
        ) == 1
    );
}

static void test_checksum_detects_corruption(void)
{
    const uint8_t source_ip[] = {
        10, 0, 0, 10
    };

    const uint8_t destination_ip[] = {
        10, 0, 0, 1
    };

    const uint8_t payload[] = {
        0xAA, 0xBB,
        0xCC, 0xDD
    };

    udp_packet_t packet;

    assert(
        udp_build(
            &packet,
            12345,
            54321,
            payload,
            sizeof(payload)
        ) == 0
    );

    uint8_t buffer[64];

    size_t len =
        udp_serialize_ipv4(
            &packet,
            source_ip,
            destination_ip,
            buffer,
            sizeof(buffer)
        );

    assert(len > 0);

    buffer[
        UDP_HEADER_LEN
    ] ^= 0x01;

    assert(
        udp_checksum_ipv4_valid(
            source_ip,
            destination_ip,
            buffer,
            len
        ) == 0
    );
}

static void test_parse_checksum_field(void)
{
    const uint8_t raw[] = {
        0xC3, 0x50,
        0x00, 0x35,
        0x00, 0x0C,
        0x12, 0x34,

        0xDE, 0xAD,
        0xBE, 0xEF
    };

    udp_packet_t packet;

    assert(
        udp_parse(
            raw,
            sizeof(raw),
            &packet
        ) == 0
    );

    assert(
        packet.source_port ==
        50000
    );

    assert(
        packet.destination_port ==
        53
    );

    assert(
        packet.length ==
        sizeof(raw)
    );

    assert(
        packet.checksum ==
        0x1234
    );

    assert(
        packet.payload_len ==
        4
    );
}

static void test_reject_short_packet(void)
{
    const uint8_t raw[] = {
        0x00, 0x35,
        0x00, 0x35
    };

    udp_packet_t packet;

    assert(
        udp_parse(
            raw,
            sizeof(raw),
            &packet
        ) == -2
    );
}

static void test_reject_bad_length(void)
{
    const uint8_t raw[] = {
        0x00, 0x35,
        0x00, 0x35,

        /*
         * Claims length = 4, which is smaller
         * than the UDP header.
         */
        0x00, 0x04,

        0x00, 0x00
    };

    udp_packet_t packet;

    assert(
        udp_parse(
            raw,
            sizeof(raw),
            &packet
        ) == -3
    );
}

static void test_reject_length_larger_than_buffer(void)
{
    const uint8_t raw[] = {
        0x00, 0x35,
        0x00, 0x35,

        /*
         * Claims 100 bytes.
         */
        0x00, 0x64,

        0x00, 0x00
    };

    udp_packet_t packet;

    assert(
        udp_parse(
            raw,
            sizeof(raw),
            &packet
        ) == -3
    );
}

static void test_small_output_buffer(void)
{
    const uint8_t payload[] = {
        1, 2, 3, 4
    };

    udp_packet_t packet;

    assert(
        udp_build(
            &packet,
            1,
            2,
            payload,
            sizeof(payload)
        ) == 0
    );

    uint8_t buffer[5];

    assert(
        udp_serialize(
            &packet,
            buffer,
            sizeof(buffer)
        ) == 0
    );
}

int main(void)
{
    test_build();
    test_basic_serialization();
    test_round_trip();

    test_ipv4_checksum();
    test_checksum_detects_corruption();

    test_parse_checksum_field();

    test_reject_short_packet();
    test_reject_bad_length();
    test_reject_length_larger_than_buffer();
    test_small_output_buffer();

    printf(
        "[PASS] UDP packet construction\n"
        "[PASS] UDP serialization\n"
        "[PASS] UDP parsing\n"
        "[PASS] UDP round-trip\n"
        "[PASS] UDP IPv4 pseudo-header checksum\n"
        "[PASS] UDP corruption detection\n"
        "[PASS] UDP wire-format validation\n"
        "[PASS] Invalid UDP rejection\n"
        "\n"
        "BLACKTERM // NETSTACK UDP tests passed.\n"
    );

    return 0;
}
