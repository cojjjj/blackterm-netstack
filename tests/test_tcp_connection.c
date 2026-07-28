#include "tcp_connection.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void establish_connection(
    tcp_connection_t *connection
)
{
    tcp_connection_init(
        connection,
        40000,
        80,
        1000
    );

    tcp_segment_t syn;

    assert(
        tcp_connection_build_syn(
            connection,
            &syn,
            64240
        ) == 0
    );

    tcp_segment_t syn_ack;

    assert(
        tcp_build(
            &syn_ack,
            80,
            40000,
            9000,
            1001,
            TCP_FLAG_SYN |
            TCP_FLAG_ACK,
            65535,
            NULL,
            0
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            connection,
            &syn_ack
        ) == 1
    );

    assert(
        connection->state ==
        TCP_STATE_ESTABLISHED
    );

    assert(
        connection->receive_next ==
        9001
    );
}

static void test_handshake(void)
{
    tcp_connection_t connection;

    tcp_connection_init(
        &connection,
        40000,
        80,
        1000
    );

    assert(
        connection.state ==
        TCP_STATE_CLOSED
    );

    tcp_segment_t syn;

    assert(
        tcp_connection_build_syn(
            &connection,
            &syn,
            64240
        ) == 0
    );

    assert(
        connection.state ==
        TCP_STATE_SYN_SENT
    );

    assert(
        syn.sequence_number ==
        1000
    );

    assert(
        connection.send_next ==
        1001
    );

    tcp_segment_t syn_ack;

    assert(
        tcp_build(
            &syn_ack,
            80,
            40000,
            9000,
            1001,
            TCP_FLAG_SYN |
            TCP_FLAG_ACK,
            65535,
            NULL,
            0
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &syn_ack
        ) == 1
    );

    assert(
        connection.state ==
        TCP_STATE_ESTABLISHED
    );

    assert(
        connection.receive_next ==
        9001
    );

    assert(
        connection.send_unacknowledged ==
        1001
    );
}

static void test_data_send_and_ack(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    const uint8_t data[] =
        "hello";

    tcp_segment_t outbound;

    assert(
        tcp_connection_build_data(
            &connection,
            &outbound,
            data,
            5,
            64240
        ) == 0
    );

    assert(
        outbound.sequence_number ==
        1001
    );

    assert(
        connection.send_next ==
        1006
    );

    tcp_segment_t ack;

    assert(
        tcp_build(
            &ack,
            80,
            40000,
            9001,
            1006,
            TCP_FLAG_ACK,
            65535,
            NULL,
            0
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &ack
        ) == 0
    );

    assert(
        connection.send_unacknowledged ==
        1006
    );

    assert(
        connection.has_retransmit_segment ==
        0
    );
}

static void test_receive_data(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    const uint8_t payload[] =
        "BLACKTERM";

    tcp_segment_t segment;

    assert(
        tcp_build(
            &segment,
            80,
            40000,
            9001,
            1001,
            TCP_FLAG_PSH |
            TCP_FLAG_ACK,
            65535,
            payload,
            sizeof(payload) - 1
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    assert(
        connection.receive_next ==
        9010
    );

    assert(
        tcp_connection_readable(
            &connection
        ) == 9
    );

    uint8_t output[32] = {0};

    assert(
        tcp_connection_read(
            &connection,
            output,
            sizeof(output)
        ) == 9
    );

    assert(
        memcmp(
            output,
            "BLACKTERM",
            9
        ) == 0
    );
}

static void test_out_of_order_reassembly(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    /*
     * Expected:
     *
     * 9001 AAAA
     * 9005 BBBB
     * 9009 CCCC
     *
     * Receive CCCC first.
     */
    const uint8_t c[] =
        "CCCC";

    tcp_segment_t segment_c;

    assert(
        tcp_build(
            &segment_c,
            80,
            40000,
            9009,
            1001,
            TCP_FLAG_PSH |
            TCP_FLAG_ACK,
            65535,
            c,
            4
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment_c
        ) == 0
    );

    assert(
        connection.receive_next ==
        9001
    );

    assert(
        tcp_connection_reassembly_count(
            &connection
        ) == 1
    );

    assert(
        tcp_connection_readable(
            &connection
        ) == 0
    );

    /*
     * Receive AAAA.
     */
    const uint8_t a[] =
        "AAAA";

    tcp_segment_t segment_a;

    assert(
        tcp_build(
            &segment_a,
            80,
            40000,
            9001,
            1001,
            TCP_FLAG_PSH |
            TCP_FLAG_ACK,
            65535,
            a,
            4
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment_a
        ) == 0
    );

    assert(
        connection.receive_next ==
        9005
    );

    /*
     * CCCC remains queued because BBBB is missing.
     */
    assert(
        tcp_connection_reassembly_count(
            &connection
        ) == 1
    );

    /*
     * Receive BBBB.
     *
     * This should deliver BBBB and immediately promote CCCC.
     */
    const uint8_t b[] =
        "BBBB";

    tcp_segment_t segment_b;

    assert(
        tcp_build(
            &segment_b,
            80,
            40000,
            9005,
            1001,
            TCP_FLAG_PSH |
            TCP_FLAG_ACK,
            65535,
            b,
            4
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment_b
        ) == 0
    );

    assert(
        connection.receive_next ==
        9013
    );

    assert(
        tcp_connection_reassembly_count(
            &connection
        ) == 0
    );

    assert(
        tcp_connection_readable(
            &connection
        ) == 12
    );

    uint8_t output[32] = {0};

    size_t length =
        tcp_connection_read(
            &connection,
            output,
            sizeof(output)
        );

    assert(length == 12);

    assert(
        memcmp(
            output,
            "AAAABBBBCCCC",
            12
        ) == 0
    );
}

static void test_multiple_buffered_segments(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    const uint8_t d[] =
        "DDDD";

    const uint8_t c[] =
        "CCCC";

    const uint8_t b[] =
        "BBBB";

    const uint8_t a[] =
        "AAAA";

    tcp_segment_t segment;

    /*
     * D
     */
    assert(
        tcp_build(
            &segment,
            80,
            40000,
            9013,
            1001,
            TCP_FLAG_ACK,
            65535,
            d,
            4
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    /*
     * C
     */
    assert(
        tcp_build(
            &segment,
            80,
            40000,
            9009,
            1001,
            TCP_FLAG_ACK,
            65535,
            c,
            4
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    /*
     * B
     */
    assert(
        tcp_build(
            &segment,
            80,
            40000,
            9005,
            1001,
            TCP_FLAG_ACK,
            65535,
            b,
            4
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    assert(
        tcp_connection_reassembly_count(
            &connection
        ) == 3
    );

    /*
     * Finally A.
     *
     * Everything should collapse into one contiguous stream.
     */
    assert(
        tcp_build(
            &segment,
            80,
            40000,
            9001,
            1001,
            TCP_FLAG_ACK,
            65535,
            a,
            4
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    assert(
        connection.receive_next ==
        9017
    );

    assert(
        tcp_connection_reassembly_count(
            &connection
        ) == 0
    );

    uint8_t output[32] = {0};

    assert(
        tcp_connection_read(
            &connection,
            output,
            sizeof(output)
        ) == 16
    );

    assert(
        memcmp(
            output,
            "AAAABBBBCCCCDDDD",
            16
        ) == 0
    );
}

static void test_duplicate_segment(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    const uint8_t payload[] =
        "HELLO";

    tcp_segment_t segment;

    assert(
        tcp_build(
            &segment,
            80,
            40000,
            9001,
            1001,
            TCP_FLAG_ACK,
            65535,
            payload,
            5
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    assert(
        connection.receive_next ==
        9006
    );

    /*
     * Same exact segment again.
     */
    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    assert(
        connection.receive_next ==
        9006
    );

    assert(
        tcp_connection_readable(
            &connection
        ) == 5
    );

    uint8_t output[16] = {0};

    assert(
        tcp_connection_read(
            &connection,
            output,
            sizeof(output)
        ) == 5
    );

    assert(
        memcmp(
            output,
            "HELLO",
            5
        ) == 0
    );
}

static void test_overlap_reassembly(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    /*
     * Receive:
     *
     * 9001..9008 = ABCDEFGH
     */
    const uint8_t first[] =
        "ABCDEFGH";

    tcp_segment_t segment;

    assert(
        tcp_build(
            &segment,
            80,
            40000,
            9001,
            1001,
            TCP_FLAG_ACK,
            65535,
            first,
            8
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    assert(
        connection.receive_next ==
        9009
    );

    /*
     * Overlap:
     *
     * starts at 9005
     *
     * EFGHIJKL
     *
     * EFGH already arrived.
     * Only IJKL should be appended.
     */
    const uint8_t overlap[] =
        "EFGHIJKL";

    assert(
        tcp_build(
            &segment,
            80,
            40000,
            9005,
            1001,
            TCP_FLAG_ACK,
            65535,
            overlap,
            8
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    assert(
        connection.receive_next ==
        9013
    );

    uint8_t output[32] = {0};

    assert(
        tcp_connection_read(
            &connection,
            output,
            sizeof(output)
        ) == 12
    );

    assert(
        memcmp(
            output,
            "ABCDEFGHIJKL",
            12
        ) == 0
    );
}

static void test_out_of_order_fin(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    /*
     * FIN says stream ends at 9009, but bytes 9001..9008
     * have not arrived yet.
     */
    tcp_segment_t fin;

    assert(
        tcp_build(
            &fin,
            80,
            40000,
            9009,
            1001,
            TCP_FLAG_FIN |
            TCP_FLAG_ACK,
            65535,
            NULL,
            0
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &fin
        ) == 0
    );

    assert(
        connection.state ==
        TCP_STATE_ESTABLISHED
    );

    assert(
        connection.pending_fin ==
        1
    );

    assert(
        connection.pending_fin_sequence ==
        9009
    );

    /*
     * Now fill the missing bytes.
     */
    const uint8_t payload[] =
        "ABCDEFGH";

    tcp_segment_t data;

    assert(
        tcp_build(
            &data,
            80,
            40000,
            9001,
            1001,
            TCP_FLAG_ACK,
            65535,
            payload,
            8
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &data
        ) == 0
    );

    /*
     * Data advances to 9009.
     *
     * Pending FIN is then consumed:
     *
     * receive_next = 9010
     */
    assert(
        connection.receive_next ==
        9010
    );

    assert(
        connection.pending_fin ==
        0
    );

    assert(
        connection.state ==
        TCP_STATE_CLOSE_WAIT
    );
}

static void test_partial_reads(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    const uint8_t payload[] =
        "BLACKTERM";

    tcp_segment_t segment;

    assert(
        tcp_build(
            &segment,
            80,
            40000,
            9001,
            1001,
            TCP_FLAG_ACK,
            65535,
            payload,
            9
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &segment
        ) == 0
    );

    uint8_t first[4] = {0};

    assert(
        tcp_connection_read(
            &connection,
            first,
            sizeof(first)
        ) == 4
    );

    assert(
        memcmp(
            first,
            "BLAC",
            4
        ) == 0
    );

    assert(
        tcp_connection_readable(
            &connection
        ) == 5
    );

    uint8_t second[8] = {0};

    assert(
        tcp_connection_read(
            &connection,
            second,
            sizeof(second)
        ) == 5
    );

    assert(
        memcmp(
            second,
            "KTERM",
            5
        ) == 0
    );

    assert(
        tcp_connection_readable(
            &connection
        ) == 0
    );
}

static void test_retransmission(void)
{
    tcp_connection_t connection;

    tcp_connection_init(
        &connection,
        40000,
        80,
        1000
    );

    tcp_segment_t syn;

    assert(
        tcp_connection_build_syn(
            &connection,
            &syn,
            64240
        ) == 0
    );

    tcp_segment_t retransmit;

    assert(
        tcp_connection_tick(
            &connection,
            500,
            &retransmit
        ) == 0
    );

    assert(
        tcp_connection_tick(
            &connection,
            500,
            &retransmit
        ) == 1
    );

    assert(
        retransmit.flags ==
        TCP_FLAG_SYN
    );

    assert(
        retransmit.sequence_number ==
        1000
    );

    assert(
        connection.retransmit_count ==
        1
    );

    assert(
        connection.retransmit_timeout_ms ==
        2000
    );
}

static void test_fin(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    tcp_segment_t fin;

    assert(
        tcp_connection_build_fin(
            &connection,
            &fin,
            64240
        ) == 0
    );

    assert(
        connection.state ==
        TCP_STATE_FIN_WAIT_1
    );

    assert(
        connection.send_next ==
        1002
    );

    tcp_segment_t ack;

    assert(
        tcp_build(
            &ack,
            80,
            40000,
            9001,
            1002,
            TCP_FLAG_ACK,
            65535,
            NULL,
            0
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &ack
        ) == 0
    );

    assert(
        connection.state ==
        TCP_STATE_FIN_WAIT_2
    );
}

static void test_remote_fin(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    tcp_segment_t fin;

    assert(
        tcp_build(
            &fin,
            80,
            40000,
            9001,
            1001,
            TCP_FLAG_FIN |
            TCP_FLAG_ACK,
            65535,
            NULL,
            0
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &fin
        ) == 0
    );

    assert(
        connection.state ==
        TCP_STATE_CLOSE_WAIT
    );

    assert(
        connection.receive_next ==
        9002
    );
}

static void test_reset(void)
{
    tcp_connection_t connection;

    establish_connection(
        &connection
    );

    tcp_segment_t rst;

    assert(
        tcp_build(
            &rst,
            80,
            40000,
            0,
            0,
            TCP_FLAG_RST,
            0,
            NULL,
            0
        ) == 0
    );

    assert(
        tcp_connection_on_segment(
            &connection,
            &rst
        ) == 0
    );

    assert(
        connection.state ==
        TCP_STATE_RESET
    );

    assert(
        tcp_connection_reassembly_count(
            &connection
        ) == 0
    );
}

static void test_state_names(void)
{
    assert(
        strcmp(
            tcp_connection_state_name(
                TCP_STATE_CLOSED
            ),
            "CLOSED"
        ) == 0
    );

    assert(
        strcmp(
            tcp_connection_state_name(
                TCP_STATE_ESTABLISHED
            ),
            "ESTABLISHED"
        ) == 0
    );

    assert(
        strcmp(
            tcp_connection_state_name(
                TCP_STATE_TIME_WAIT
            ),
            "TIME-WAIT"
        ) == 0
    );
}

int main(void)
{
    test_handshake();

    test_data_send_and_ack();
    test_receive_data();

    test_out_of_order_reassembly();
    test_multiple_buffered_segments();

    test_duplicate_segment();
    test_overlap_reassembly();

    test_out_of_order_fin();

    test_partial_reads();

    test_retransmission();

    test_fin();
    test_remote_fin();

    test_reset();

    test_state_names();

    printf(
        "[PASS] TCP connection initialization\n"
        "[PASS] SYN-SENT transition\n"
        "[PASS] ESTABLISHED transition\n"
        "[PASS] TCP sequence tracking\n"
        "[PASS] TCP acknowledgment tracking\n"
        "[PASS] TCP receive delivery\n"
        "[PASS] TCP out-of-order buffering\n"
        "[PASS] TCP multi-segment reassembly\n"
        "[PASS] TCP duplicate suppression\n"
        "[PASS] TCP overlap handling\n"
        "[PASS] TCP deferred FIN handling\n"
        "[PASS] TCP partial application reads\n"
        "[PASS] TCP retransmission timer\n"
        "[PASS] TCP exponential backoff\n"
        "[PASS] TCP FIN state handling\n"
        "[PASS] TCP RST handling\n"
        "[PASS] TCP state names\n"
        "\n"
        "BLACKTERM // NETSTACK TCP reassembly tests passed.\n"
    );

    return 0;
}
