#include "ipv4.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_checksum_known_header(void)
{
    /*
     * IPv4 header with checksum field zeroed.
     *
     * Expected checksum: 0xB755
     */
    const uint8_t header[] = {
        0x45, 0x00,
        0x00, 0x54,
        0x00, 0x00,
        0x40, 0x00,
        0x40,
        0x01,
        0x00, 0x00,

        0xC0, 0xA8, 0x01, 0x01,
        0xC0, 0xA8, 0x01, 0x02
    };

    uint16_t checksum =
        ipv4_checksum(header, sizeof(header));

    assert(checksum == 0xB755);
}

static void test_build_ipv4_packet(void)
{
    const uint8_t source_ip[] = {
        192, 168, 1, 50
    };

    const uint8_t destination_ip[] = {
        192, 168, 1, 1
    };

    const uint8_t payload[] = {
        0xDE, 0xAD, 0xBE, 0xEF
    };

    ipv4_packet_t packet;

    int result = ipv4_build(
        &packet,
        source_ip,
        destination_ip,
        IPV4_PROTOCOL_ICMP,
        payload,
        sizeof(payload),
        64,
        0x1234
    );

    assert(result == 0);

    assert(packet.version == 4);
    assert(packet.ihl == 5);

    assert(packet.total_length == 24);

    assert(packet.identification == 0x1234);

    assert(packet.flags == IPV4_FLAG_DF);
    assert(packet.fragment_offset == 0);

    assert(packet.ttl == 64);
    assert(packet.protocol == IPV4_PROTOCOL_ICMP);

    assert(
        memcmp(
            packet.source_ip,
            source_ip,
            IPV4_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            packet.destination_ip,
            destination_ip,
            IPV4_ADDR_LEN
        ) == 0
    );

    assert(packet.payload_len == sizeof(payload));

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
    const uint8_t source_ip[] = {
        10, 0, 0, 10
    };

    const uint8_t destination_ip[] = {
        10, 0, 0, 1
    };

    const uint8_t payload[] = {
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    ipv4_packet_t original;

    assert(
        ipv4_build(
            &original,
            source_ip,
            destination_ip,
            IPV4_PROTOCOL_UDP,
            payload,
            sizeof(payload),
            64,
            0xABCD
        ) == 0
    );

    uint8_t serialized[IPV4_MAX_PACKET_LEN];

    size_t serialized_len = ipv4_serialize(
        &original,
        serialized,
        sizeof(serialized)
    );

    assert(
        serialized_len ==
        IPV4_MIN_HEADER_LEN + sizeof(payload)
    );

    /*
     * A serialized IPv4 header including the checksum
     * should produce a checksum result of zero.
     */
    assert(
        ipv4_checksum(
            serialized,
            IPV4_MIN_HEADER_LEN
        ) == 0
    );

    ipv4_packet_t parsed;

    assert(
        ipv4_parse(
            serialized,
            serialized_len,
            &parsed
        ) == 0
    );

    assert(parsed.version == original.version);
    assert(parsed.ihl == original.ihl);

    assert(
        parsed.total_length ==
        serialized_len
    );

    assert(
        parsed.identification ==
        original.identification
    );

    assert(parsed.flags == original.flags);

    assert(
        parsed.fragment_offset ==
        original.fragment_offset
    );

    assert(parsed.ttl == original.ttl);
    assert(parsed.protocol == original.protocol);

    assert(
        memcmp(
            parsed.source_ip,
            original.source_ip,
            IPV4_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            parsed.destination_ip,
            original.destination_ip,
            IPV4_ADDR_LEN
        ) == 0
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

    assert(parsed.header_checksum != 0);
}

static void test_protocol_names(void)
{
    assert(
        strcmp(
            ipv4_protocol_name(IPV4_PROTOCOL_ICMP),
            "ICMP"
        ) == 0
    );

    assert(
        strcmp(
            ipv4_protocol_name(IPV4_PROTOCOL_TCP),
            "TCP"
        ) == 0
    );

    assert(
        strcmp(
            ipv4_protocol_name(IPV4_PROTOCOL_UDP),
            "UDP"
        ) == 0
    );

    assert(
        strcmp(
            ipv4_protocol_name(255),
            "Unknown"
        ) == 0
    );
}

static void test_address_formatting(void)
{
    const uint8_t ip[] = {
        172, 16, 25, 200
    };

    char output[16];

    assert(
        ipv4_address_to_string(
            ip,
            output,
            sizeof(output)
        ) == 0
    );

    assert(
        strcmp(
            output,
            "172.16.25.200"
        ) == 0
    );
}

static void test_reject_short_packet(void)
{
    const uint8_t packet[] = {
        0x45,
        0x00,
        0x00,
        0x00
    };

    ipv4_packet_t parsed;

    assert(
        ipv4_parse(
            packet,
            sizeof(packet),
            &parsed
        ) == -2
    );
}

static void test_reject_ipv6(void)
{
    uint8_t packet[IPV4_MIN_HEADER_LEN] = {0};

    packet[0] = 0x65;

    ipv4_packet_t parsed;

    assert(
        ipv4_parse(
            packet,
            sizeof(packet),
            &parsed
        ) == -3
    );
}

static void test_reject_invalid_ihl(void)
{
    uint8_t packet[IPV4_MIN_HEADER_LEN] = {0};

    packet[0] = 0x44;

    ipv4_packet_t parsed;

    assert(
        ipv4_parse(
            packet,
            sizeof(packet),
            &parsed
        ) == -4
    );
}

static void test_reject_invalid_total_length(void)
{
    uint8_t packet[IPV4_MIN_HEADER_LEN] = {0};

    packet[0] = 0x45;

    packet[2] = 0x00;
    packet[3] = 0x0A;

    ipv4_packet_t parsed;

    assert(
        ipv4_parse(
            packet,
            sizeof(packet),
            &parsed
        ) == -5
    );
}

static void test_reject_bad_checksum(void)
{
    const uint8_t source_ip[] = {
        192, 168, 1, 10
    };

    const uint8_t destination_ip[] = {
        192, 168, 1, 1
    };

    ipv4_packet_t packet;

    assert(
        ipv4_build(
            &packet,
            source_ip,
            destination_ip,
            IPV4_PROTOCOL_ICMP,
            NULL,
            0,
            64,
            1
        ) == 0
    );

    uint8_t serialized[IPV4_MIN_HEADER_LEN];

    assert(
        ipv4_serialize(
            &packet,
            serialized,
            sizeof(serialized)
        ) == IPV4_MIN_HEADER_LEN
    );

    /*
     * Corrupt TTL after checksum calculation.
     */
    serialized[8] ^= 0x01;

    ipv4_packet_t parsed;

    assert(
        ipv4_parse(
            serialized,
            sizeof(serialized),
            &parsed
        ) == -6
    );
}

static void test_wire_fields(void)
{
    const uint8_t source_ip[] = {
        192, 168, 50, 10
    };

    const uint8_t destination_ip[] = {
        8, 8, 8, 8
    };

    ipv4_packet_t packet;

    assert(
        ipv4_build(
            &packet,
            source_ip,
            destination_ip,
            IPV4_PROTOCOL_UDP,
            NULL,
            0,
            64,
            0x1337
        ) == 0
    );

    uint8_t serialized[IPV4_MIN_HEADER_LEN];

    assert(
        ipv4_serialize(
            &packet,
            serialized,
            sizeof(serialized)
        ) == IPV4_MIN_HEADER_LEN
    );

    assert(serialized[0] == 0x45);

    assert(serialized[2] == 0x00);
    assert(serialized[3] == 0x14);

    assert(serialized[4] == 0x13);
    assert(serialized[5] == 0x37);

    assert(serialized[6] == 0x40);
    assert(serialized[7] == 0x00);

    assert(serialized[8] == 64);
    assert(serialized[9] == IPV4_PROTOCOL_UDP);

    assert(
        memcmp(
            serialized + 12,
            source_ip,
            IPV4_ADDR_LEN
        ) == 0
    );

    assert(
        memcmp(
            serialized + 16,
            destination_ip,
            IPV4_ADDR_LEN
        ) == 0
    );

    /*
     * Verify the generated header checksum is valid.
     */
    assert(
        ipv4_checksum(
            serialized,
            IPV4_MIN_HEADER_LEN
        ) == 0
    );
}

int main(void)
{
    test_checksum_known_header();
    test_build_ipv4_packet();
    test_round_trip();

    test_protocol_names();
    test_address_formatting();

    test_reject_short_packet();
    test_reject_ipv6();
    test_reject_invalid_ihl();
    test_reject_invalid_total_length();
    test_reject_bad_checksum();

    test_wire_fields();

    printf(
        "[PASS] IPv4 checksum\n"
        "[PASS] IPv4 packet construction\n"
        "[PASS] IPv4 serialization\n"
        "[PASS] IPv4 parsing\n"
        "[PASS] IPv4 round-trip\n"
        "[PASS] IPv4 wire-format validation\n"
        "[PASS] IPv4 address formatting\n"
        "[PASS] IPv4 protocol identification\n"
        "[PASS] Invalid packet rejection\n"
        "\n"
        "BLACKTERM // NETSTACK IPv4 tests passed.\n"
    );

    return 0;
}
