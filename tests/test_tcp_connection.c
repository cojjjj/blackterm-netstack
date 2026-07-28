#include "tcp_connection.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

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

    tcp_connection_init(
        &connection,
        40000,
        80,
        1000
    );

    connection.state =
        TCP_STATE_ESTABLISHED;

    connection.send_next =
        1001;

    connection.send_unacknowledged =
        1001;

    connection.receive_next =
        9001;

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

    tcp_connection_init(
        &connection,
        40000,
        80,
        1000
    );

    connection.state =
        TCP_STATE_ESTABLISHED;

    connection.send_next =
        1001;

    connection.send_unacknowledged =
        1001;

    connection.receive_next =
        9001;

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

    tcp_connection_init(
        &connection,
        40000,
        80,
        1000
    );

    connection.state =
        TCP_STATE_ESTABLISHED;

    connection.send_next =
        1001;

    connection.send_unacknowledged =
        1001;

    connection.receive_next =
        9001;

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

    tcp_connection_init(
        &connection,
        40000,
        80,
        1000
    );

    connection.state =
        TCP_STATE_ESTABLISHED;

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
        "[PASS] TCP receive tracking\n"
        "[PASS] TCP retransmission timer\n"
        "[PASS] TCP exponential backoff\n"
        "[PASS] TCP FIN state handling\n"
        "[PASS] TCP RST handling\n"
        "[PASS] TCP state names\n"
        "\n"
        "BLACKTERM // NETSTACK TCP connection tests passed.\n"
    );

    return 0;
}
