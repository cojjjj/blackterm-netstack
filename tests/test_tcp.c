#include "tcp.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_build_syn(void)
{
    tcp_segment_t segment;

    assert(
        tcp_build(
            &segment,
            50000,
            80,
            0x12345678,
            0,
            TCP_FLAG_SYN,
            64240,
            NULL,
            0
        ) == 0
    );

    assert(
        segment.source_port ==
        50000
    );

    assert(
        segment.destination_port ==
        80
    );

    assert(
        segment.sequence_number ==
        0x12345678
    );

    assert(
        segment.acknowledgment_number ==
        0
    );

    assert(
        segment.flags ==
        TCP_FLAG_SYN
    );

    assert(
        segment.data_offset ==
        5
    );

    assert(
        segment.window_size ==
        64240
    );
}

static void test_wire_format(void)
{
    tcp_segment_t segment;

    assert(
        tcp_build(
            &segment,
            0xC350,
            80,
            0x11223344,
            0x55667788,
            TCP_FLAG_ACK,
            0x4000,
            NULL,
            0
        ) == 0
    );

    uint8_t bytes[64];

    size_t length =
        tcp_serialize(
            &segment,
            bytes,
            sizeof(bytes)
        );

    assert(
        length ==
        TCP_MIN_HEADER_LEN
    );

    assert(bytes[0] == 0xC3);
    assert(bytes[1] == 0x50);

    assert(bytes[2] == 0x00);
    assert(bytes[3] == 0x50);

    assert(bytes[4] == 0x11);
    assert(bytes[5] == 0x22);
    assert(bytes[6] == 0x33);
    assert(bytes[7] == 0x44);

    assert(bytes[8] == 0x55);
    assert(bytes[9] == 0x66);
    assert(bytes[10] == 0x77);
    assert(bytes[11] == 0x88);

    /*
     * data offset = 5
     */
    assert(bytes[12] == 0x50);

    assert(
        bytes[13] ==
        TCP_FLAG_ACK
    );

    assert(bytes[14] == 0x40);
    assert(bytes[15] == 0x00);
}

static void test_round_trip(void)
{
    const uint8_t payload[] = {
        'B', 'L', 'A', 'C', 'K',
        'T', 'E', 'R', 'M'
    };

    tcp_segment_t original;

    assert(
        tcp_build(
            &original,
            40000,
            8080,
            1000,
            2000,
            TCP_FLAG_PSH |
            TCP_FLAG_ACK,
            32768,
            payload,
            sizeof(payload)
        ) == 0
    );

    uint8_t bytes[128];

    size_t length =
        tcp_serialize(
            &original,
            bytes,
            sizeof(bytes)
        );

    assert(
        length ==
        TCP_MIN_HEADER_LEN +
        sizeof(payload)
    );

    tcp_segment_t parsed;

    assert(
        tcp_parse(
            bytes,
            length,
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
        parsed.sequence_number ==
        original.sequence_number
    );

    assert(
        parsed.acknowledgment_number ==
        original.acknowledgment_number
    );

    assert(
        parsed.flags ==
        original.flags
    );

    assert(
        parsed.payload_len ==
        sizeof(payload)
    );

    assert(
        memcmp(
            parsed.payload,
            payload,
            sizeof(payload)
        ) == 0
    );
}

static void test_ipv4_checksum(void)
{
    const uint8_t source_ip[] = {
        192, 168, 50, 62
    };

    const uint8_t destination_ip[] = {
        93, 184, 216, 34
    };

    tcp_segment_t segment;

    assert(
        tcp_build(
            &segment,
            50000,
            80,
            100000,
            0,
            TCP_FLAG_SYN,
            64240,
            NULL,
            0
        ) == 0
    );

    uint8_t bytes[64];

    size_t length =
        tcp_serialize_ipv4(
            &segment,
            source_ip,
            destination_ip,
            bytes,
            sizeof(bytes)
        );

    assert(
        length ==
        TCP_MIN_HEADER_LEN
    );

    assert(
        bytes[16] != 0 ||
        bytes[17] != 0
    );

    assert(
        tcp_checksum_ipv4_valid(
            source_ip,
            destination_ip,
            bytes,
            length
        ) == 1
    );
}

static void test_checksum_corruption(void)
{
    const uint8_t source_ip[] = {
        10, 0, 0, 10
    };

    const uint8_t destination_ip[] = {
        10, 0, 0, 1
    };

    tcp_segment_t segment;

    assert(
        tcp_build(
            &segment,
            12345,
            443,
            123,
            0,
            TCP_FLAG_SYN,
            65535,
            NULL,
            0
        ) == 0
    );

    uint8_t bytes[64];

    size_t length =
        tcp_serialize_ipv4(
            &segment,
            source_ip,
            destination_ip,
            bytes,
            sizeof(bytes)
        );

    assert(length > 0);

    bytes[7] ^= 0x01;

    assert(
        tcp_checksum_ipv4_valid(
            source_ip,
            destination_ip,
            bytes,
            length
        ) == 0
    );
}

static void test_parse_syn_ack(void)
{
    tcp_segment_t original;

    assert(
        tcp_build(
            &original,
            80,
            50000,
            9000,
            1001,
            TCP_FLAG_SYN |
            TCP_FLAG_ACK,
            65535,
            NULL,
            0
        ) == 0
    );

    uint8_t bytes[64];

    size_t length =
        tcp_serialize(
            &original,
            bytes,
            sizeof(bytes)
        );

    tcp_segment_t parsed;

    assert(
        tcp_parse(
            bytes,
            length,
            &parsed
        ) == 0
    );

    assert(
        parsed.flags ==
        (TCP_FLAG_SYN |
        TCP_FLAG_ACK)
    );

    assert(
        parsed.sequence_number ==
        9000
    );

    assert(
        parsed.acknowledgment_number ==
        1001
    );
}

static void test_flag_names(void)
{
    assert(
        strcmp(
            tcp_state_flag_name(
                TCP_FLAG_SYN
            ),
            "SYN"
        ) == 0
    );

    assert(
        strcmp(
            tcp_state_flag_name(
                TCP_FLAG_SYN |
                TCP_FLAG_ACK
            ),
            "SYN-ACK"
        ) == 0
    );

    assert(
        strcmp(
            tcp_state_flag_name(
                TCP_FLAG_ACK
            ),
            "ACK"
        ) == 0
    );

    assert(
        strcmp(
            tcp_state_flag_name(
                TCP_FLAG_RST
            ),
            "RST"
        ) == 0
    );

    assert(
        strcmp(
            tcp_state_flag_name(
                TCP_FLAG_FIN
            ),
            "FIN"
        ) == 0
    );
}

static void test_reject_short_segment(void)
{
    uint8_t bytes[10] = {0};

    tcp_segment_t segment;

    assert(
        tcp_parse(
            bytes,
            sizeof(bytes),
            &segment
        ) == -2
    );
}

static void test_reject_bad_data_offset(void)
{
    uint8_t bytes[
        TCP_MIN_HEADER_LEN
    ] = {0};

    /*
     * Invalid header size:
     * 4 * 4 = 16 bytes.
     */
    bytes[12] = 0x40;

    tcp_segment_t segment;

    assert(
        tcp_parse(
            bytes,
            sizeof(bytes),
            &segment
        ) == -3
    );
}

int main(void)
{
    test_build_syn();
    test_wire_format();
    test_round_trip();

    test_ipv4_checksum();
    test_checksum_corruption();

    test_parse_syn_ack();
    test_flag_names();

    test_reject_short_segment();
    test_reject_bad_data_offset();

    printf(
        "[PASS] TCP SYN construction\n"
        "[PASS] TCP header serialization\n"
        "[PASS] TCP parsing\n"
        "[PASS] TCP round-trip\n"
        "[PASS] TCP IPv4 pseudo-header checksum\n"
        "[PASS] TCP corruption detection\n"
        "[PASS] TCP SYN-ACK parsing\n"
        "[PASS] TCP flag decoding\n"
        "[PASS] Invalid TCP rejection\n"
        "\n"
        "BLACKTERM // NETSTACK TCP core tests passed.\n"
    );

    return 0;
}
