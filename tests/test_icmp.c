#include "icmp.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_checksum_known_packet(void)
{
    /*
     * Echo request:
     *
     * Type:       8
     * Code:       0
     * Checksum:   zero while calculating
     * Identifier: 0x1234
     * Sequence:   1
     * Payload:    "ABCD"
     */
    const uint8_t packet[] = {
        0x08, 0x00,
        0x00, 0x00,

        0x12, 0x34,
        0x00, 0x01,

        0x41, 0x42,
        0x43, 0x44
    };

    uint16_t checksum =
        icmp_checksum(packet, sizeof(packet));

    assert(checksum == 0x6144);
}

static void test_build_echo_request(void)
{
    const uint8_t payload[] = {
        'B', 'L', 'A', 'C', 'K',
        'T', 'E', 'R', 'M'
    };

    icmp_packet_t packet;

    assert(
        icmp_build_echo_request(
            &packet,
            0x1234,
            1,
            payload,
            sizeof(payload)
        ) == 0
    );

    assert(packet.type == ICMP_TYPE_ECHO_REQUEST);
    assert(packet.code == ICMP_CODE_ECHO);

    assert(packet.identifier == 0x1234);
    assert(packet.sequence == 1);

    assert(packet.payload_len == sizeof(payload));

    assert(
        memcmp(
            packet.payload,
            payload,
            sizeof(payload)
        ) == 0
    );
}

static void test_build_echo_reply(void)
{
    const uint8_t payload[] = {
        0x01, 0x02, 0x03, 0x04
    };

    icmp_packet_t packet;

    assert(
        icmp_build_echo_reply(
            &packet,
            0xBEEF,
            7,
            payload,
            sizeof(payload)
        ) == 0
    );

    assert(packet.type == ICMP_TYPE_ECHO_REPLY);
    assert(packet.code == ICMP_CODE_ECHO);

    assert(packet.identifier == 0xBEEF);
    assert(packet.sequence == 7);

    assert(
        memcmp(
            packet.payload,
            payload,
            sizeof(payload)
        ) == 0
    );
}

static void test_round_trip(void)
{
    const uint8_t payload[] = {
        'n', 'e', 't', 's', 't', 'a', 'c', 'k'
    };

    icmp_packet_t original;

    assert(
        icmp_build_echo_request(
            &original,
            0xCAFE,
            42,
            payload,
            sizeof(payload)
        ) == 0
    );

    uint8_t serialized[ICMP_MAX_PACKET_LEN];

    size_t serialized_len = icmp_serialize(
        &original,
        serialized,
        sizeof(serialized)
    );

    assert(
        serialized_len ==
        ICMP_ECHO_HEADER_LEN + sizeof(payload)
    );

    /*
     * Entire serialized ICMP packet should validate to zero.
     */
    assert(
        icmp_checksum(
            serialized,
            serialized_len
        ) == 0
    );

    icmp_packet_t parsed;

    assert(
        icmp_parse(
            serialized,
            serialized_len,
            &parsed
        ) == 0
    );

    assert(parsed.type == original.type);
    assert(parsed.code == original.code);

    assert(
        parsed.identifier ==
        original.identifier
    );

    assert(
        parsed.sequence ==
        original.sequence
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

    assert(parsed.checksum != 0);
}

static void test_wire_fields(void)
{
    icmp_packet_t packet;

    assert(
        icmp_build_echo_request(
            &packet,
            0x1337,
            0x0042,
            NULL,
            0
        ) == 0
    );

    uint8_t serialized[ICMP_ECHO_HEADER_LEN];

    assert(
        icmp_serialize(
            &packet,
            serialized,
            sizeof(serialized)
        ) == ICMP_ECHO_HEADER_LEN
    );

    assert(serialized[0] == ICMP_TYPE_ECHO_REQUEST);
    assert(serialized[1] == ICMP_CODE_ECHO);

    assert(serialized[4] == 0x13);
    assert(serialized[5] == 0x37);

    assert(serialized[6] == 0x00);
    assert(serialized[7] == 0x42);

    assert(
        icmp_checksum(
            serialized,
            sizeof(serialized)
        ) == 0
    );
}

static void test_type_names(void)
{
    assert(
        strcmp(
            icmp_type_name(ICMP_TYPE_ECHO_REQUEST),
            "Echo Request"
        ) == 0
    );

    assert(
        strcmp(
            icmp_type_name(ICMP_TYPE_ECHO_REPLY),
            "Echo Reply"
        ) == 0
    );

    assert(
        strcmp(
            icmp_type_name(99),
            "Unknown"
        ) == 0
    );
}

static void test_reject_short_packet(void)
{
    const uint8_t packet[] = {
        0x08, 0x00,
        0x00, 0x00
    };

    icmp_packet_t parsed;

    assert(
        icmp_parse(
            packet,
            sizeof(packet),
            &parsed
        ) == -2
    );
}

static void test_reject_unsupported_type(void)
{
    uint8_t packet[ICMP_ECHO_HEADER_LEN] = {
        0x03, 0x00,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x01
    };

    icmp_packet_t parsed;

    assert(
        icmp_parse(
            packet,
            sizeof(packet),
            &parsed
        ) == -3
    );
}

static void test_reject_bad_code(void)
{
    uint8_t packet[ICMP_ECHO_HEADER_LEN] = {
        0x08, 0x01,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x01
    };

    icmp_packet_t parsed;

    assert(
        icmp_parse(
            packet,
            sizeof(packet),
            &parsed
        ) == -4
    );
}

static void test_reject_bad_checksum(void)
{
    icmp_packet_t packet;

    assert(
        icmp_build_echo_request(
            &packet,
            0x1234,
            1,
            NULL,
            0
        ) == 0
    );

    uint8_t serialized[ICMP_ECHO_HEADER_LEN];

    assert(
        icmp_serialize(
            &packet,
            serialized,
            sizeof(serialized)
        ) == ICMP_ECHO_HEADER_LEN
    );

    /*
     * Corrupt sequence number after checksum generation.
     */
    serialized[7] ^= 0x01;

    icmp_packet_t parsed;

    assert(
        icmp_parse(
            serialized,
            sizeof(serialized),
            &parsed
        ) == -5
    );
}

static void test_small_output_buffer(void)
{
    const uint8_t payload[] = {
        0xAA, 0xBB, 0xCC, 0xDD
    };

    icmp_packet_t packet;

    assert(
        icmp_build_echo_request(
            &packet,
            1,
            1,
            payload,
            sizeof(payload)
        ) == 0
    );

    uint8_t buffer[5];

    assert(
        icmp_serialize(
            &packet,
            buffer,
            sizeof(buffer)
        ) == 0
    );
}

int main(void)
{
    test_checksum_known_packet();

    test_build_echo_request();
    test_build_echo_reply();

    test_round_trip();
    test_wire_fields();

    test_type_names();

    test_reject_short_packet();
    test_reject_unsupported_type();
    test_reject_bad_code();
    test_reject_bad_checksum();
    test_small_output_buffer();

    printf(
        "[PASS] ICMP checksum\n"
        "[PASS] ICMP Echo Request construction\n"
        "[PASS] ICMP Echo Reply construction\n"
        "[PASS] ICMP serialization\n"
        "[PASS] ICMP parsing\n"
        "[PASS] ICMP round-trip\n"
        "[PASS] ICMP wire-format validation\n"
        "[PASS] ICMP type identification\n"
        "[PASS] Invalid packet rejection\n"
        "\n"
        "BLACKTERM // NETSTACK ICMP tests passed.\n"
    );

    return 0;
}
