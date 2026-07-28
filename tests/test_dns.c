#include "dns.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_build_query(void)
{
    uint8_t packet[DNS_MAX_PACKET_LEN];

    size_t len =
        dns_build_a_query(
            packet,
            sizeof(packet),
            0x1234,
            "example.com"
        );

    assert(len == 29);

    const uint8_t expected[] = {
        /*
         * ID
         */
        0x12, 0x34,

        /*
         * RD = 1
         */
        0x01, 0x00,

        /*
         * QDCOUNT = 1
         */
        0x00, 0x01,

        /*
         * ANCOUNT
         */
        0x00, 0x00,

        /*
         * NSCOUNT
         */
        0x00, 0x00,

        /*
         * ARCOUNT
         */
        0x00, 0x00,

        /*
         * example.com
         */
        0x07,
        'e', 'x', 'a', 'm',
        'p', 'l', 'e',

        0x03,
        'c', 'o', 'm',

        0x00,

        /*
         * Type A
         */
        0x00, 0x01,

        /*
         * Class IN
         */
        0x00, 0x01
    };

    assert(
        sizeof(expected) ==
        len
    );

    assert(
        memcmp(
            packet,
            expected,
            sizeof(expected)
        ) == 0
    );
}

static void test_parse_response(void)
{
    /*
     * Synthetic response:
     *
     * example.com A 93.184.216.34
     *
     * Answer NAME uses a compression pointer to offset 12.
     */
    const uint8_t packet[] = {
        /*
         * ID
         */
        0x12, 0x34,

        /*
         * QR=1, RD=1, RA=1, RCODE=0
         */
        0x81, 0x80,

        /*
         * QDCOUNT = 1
         */
        0x00, 0x01,

        /*
         * ANCOUNT = 1
         */
        0x00, 0x01,

        /*
         * NSCOUNT
         */
        0x00, 0x00,

        /*
         * ARCOUNT
         */
        0x00, 0x00,

        /*
         * Question:
         * example.com
         */
        0x07,
        'e', 'x', 'a', 'm',
        'p', 'l', 'e',

        0x03,
        'c', 'o', 'm',

        0x00,

        /*
         * QTYPE A
         */
        0x00, 0x01,

        /*
         * QCLASS IN
         */
        0x00, 0x01,

        /*
         * Answer NAME:
         * pointer -> byte 12
         */
        0xC0, 0x0C,

        /*
         * TYPE A
         */
        0x00, 0x01,

        /*
         * CLASS IN
         */
        0x00, 0x01,

        /*
         * TTL = 300
         */
        0x00, 0x00,
        0x01, 0x2C,

        /*
         * RDLENGTH = 4
         */
        0x00, 0x04,

        /*
         * 93.184.216.34
         */
        0x5D,
        0xB8,
        0xD8,
        0x22
    };

    dns_response_t response;

    assert(
        dns_parse_response(
            packet,
            sizeof(packet),
            0x1234,
            &response
        ) == 0
    );

    assert(
        response.transaction_id ==
        0x1234
    );

    assert(
        response.response_code ==
        0
    );

    assert(
        response.recursion_available ==
        1
    );

    assert(
        response.answer_count ==
        1
    );

    const uint8_t expected_ip[] = {
        93, 184, 216, 34
    };

    assert(
        memcmp(
            response.answers[0].address,
            expected_ip,
            4
        ) == 0
    );

    assert(
        response.answers[0].ttl ==
        300
    );
}

static void test_nxdomain(void)
{
    const uint8_t packet[] = {
        0xBE, 0xEF,

        /*
         * QR=1
         * RD=1
         * RA=1
         * RCODE=3 NXDOMAIN
         */
        0x81, 0x83,

        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };

    dns_response_t response;

    assert(
        dns_parse_response(
            packet,
            sizeof(packet),
            0xBEEF,
            &response
        ) == 0
    );

    assert(
        response.response_code ==
        3
    );

    assert(
        response.answer_count ==
        0
    );

    assert(
        strcmp(
            dns_response_code_name(
                response.response_code
            ),
            "NXDOMAIN"
        ) == 0
    );
}

static void test_wrong_transaction_id(void)
{
    const uint8_t packet[] = {
        0x12, 0x34,
        0x81, 0x80,

        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };

    dns_response_t response;

    assert(
        dns_parse_response(
            packet,
            sizeof(packet),
            0x9999,
            &response
        ) == -3
    );
}

static void test_reject_query_as_response(void)
{
    const uint8_t packet[] = {
        0x12, 0x34,

        /*
         * Query, not response.
         */
        0x01, 0x00,

        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };

    dns_response_t response;

    assert(
        dns_parse_response(
            packet,
            sizeof(packet),
            0x1234,
            &response
        ) == -4
    );
}

static void test_reject_bad_hostname(void)
{
    uint8_t packet[DNS_MAX_PACKET_LEN];

    assert(
        dns_build_a_query(
            packet,
            sizeof(packet),
            1,
            "example..com"
        ) == 0
    );

    assert(
        dns_build_a_query(
            packet,
            sizeof(packet),
            1,
            ""
        ) == 0
    );
}

static void test_small_buffer(void)
{
    uint8_t packet[16];

    assert(
        dns_build_a_query(
            packet,
            sizeof(packet),
            1,
            "example.com"
        ) == 0
    );
}

static void test_response_names(void)
{
    assert(
        strcmp(
            dns_response_code_name(0),
            "NOERROR"
        ) == 0
    );

    assert(
        strcmp(
            dns_response_code_name(2),
            "SERVFAIL"
        ) == 0
    );

    assert(
        strcmp(
            dns_response_code_name(3),
            "NXDOMAIN"
        ) == 0
    );

    assert(
        strcmp(
            dns_response_code_name(5),
            "REFUSED"
        ) == 0
    );
}

int main(void)
{
    test_build_query();
    test_parse_response();

    test_nxdomain();

    test_wrong_transaction_id();
    test_reject_query_as_response();

    test_reject_bad_hostname();
    test_small_buffer();

    test_response_names();

    printf(
        "[PASS] DNS A query construction\n"
        "[PASS] DNS wire-format encoding\n"
        "[PASS] DNS response parsing\n"
        "[PASS] DNS compression pointer handling\n"
        "[PASS] DNS A record extraction\n"
        "[PASS] DNS TTL parsing\n"
        "[PASS] DNS response codes\n"
        "[PASS] Invalid DNS rejection\n"
        "\n"
        "BLACKTERM // NETSTACK DNS tests passed.\n"
    );

    return 0;
}
