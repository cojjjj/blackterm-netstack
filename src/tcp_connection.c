#include "tcp_connection.h"

#include <string.h>

#define TCP_DEFAULT_RTO_MS 1000U
#define TCP_DEFAULT_RETRANSMIT_LIMIT 5U

static uint32_t segment_sequence_consumed(
    const tcp_segment_t *segment
)
{
    uint32_t consumed =
        (uint32_t)segment->payload_len;

    if (
        (segment->flags & TCP_FLAG_SYN) != 0
    ) {
        consumed++;
    }

    if (
        (segment->flags & TCP_FLAG_FIN) != 0
    ) {
        consumed++;
    }

    return consumed;
}

static void remember_for_retransmission(
    tcp_connection_t *connection,
    const tcp_segment_t *segment
)
{
    connection->last_segment =
        *segment;

    connection->has_retransmit_segment =
        1;

    connection->retransmit_elapsed_ms =
        0;
}

void tcp_connection_init(
    tcp_connection_t *connection,
    uint16_t local_port,
    uint16_t remote_port,
    uint32_t initial_sequence
)
{
    if (connection == NULL) {
        return;
    }

    memset(
        connection,
        0,
        sizeof(*connection)
    );

    connection->state =
        TCP_STATE_CLOSED;

    connection->local_port =
        local_port;

    connection->remote_port =
        remote_port;

    connection->send_unacknowledged =
        initial_sequence;

    connection->send_next =
        initial_sequence;

    connection->receive_next =
        0;

    connection->remote_window =
        0;

    connection->retransmit_timeout_ms =
        TCP_DEFAULT_RTO_MS;

    connection->retransmit_limit =
        TCP_DEFAULT_RETRANSMIT_LIMIT;
}

int tcp_connection_build_syn(
    tcp_connection_t *connection,
    tcp_segment_t *segment,
    uint16_t window
)
{
    if (
        connection == NULL ||
        segment == NULL ||
        connection->state != TCP_STATE_CLOSED
    ) {
        return -1;
    }

    if (
        tcp_build(
            segment,
            connection->local_port,
            connection->remote_port,
            connection->send_next,
            0,
            TCP_FLAG_SYN,
            window,
            NULL,
            0
        ) != 0
    ) {
        return -1;
    }

    connection->send_unacknowledged =
        connection->send_next;

    connection->send_next++;

    connection->state =
        TCP_STATE_SYN_SENT;

    remember_for_retransmission(
        connection,
        segment
    );

    return 0;
}

int tcp_connection_on_segment(
    tcp_connection_t *connection,
    const tcp_segment_t *segment
)
{
    if (
        connection == NULL ||
        segment == NULL
    ) {
        return -1;
    }

    if (
        segment->source_port !=
        connection->remote_port ||
        segment->destination_port !=
        connection->local_port
    ) {
        return -1;
    }

    if (
        (segment->flags & TCP_FLAG_RST) != 0
    ) {
        connection->state =
            TCP_STATE_RESET;

        connection->has_retransmit_segment =
            0;

        return 0;
    }

    if (
        (segment->flags & TCP_FLAG_ACK) != 0
    ) {
        if (
            segment->acknowledgment_number >
                connection->send_unacknowledged &&
            segment->acknowledgment_number <=
                connection->send_next
        ) {
            connection->send_unacknowledged =
                segment->acknowledgment_number;

            connection->retransmit_elapsed_ms =
                0;

            connection->retransmit_count =
                0;

            if (
                connection->send_unacknowledged ==
                connection->send_next
            ) {
                connection->has_retransmit_segment =
                    0;
            }
        }
    }

    connection->remote_window =
        segment->window_size;

    if (
        connection->state ==
        TCP_STATE_SYN_SENT
    ) {
        if (
            (segment->flags &
            (TCP_FLAG_SYN | TCP_FLAG_ACK)) ==
            (TCP_FLAG_SYN | TCP_FLAG_ACK)
        ) {
            if (
                segment->acknowledgment_number !=
                connection->send_next
            ) {
                return -1;
            }

            connection->receive_next =
                segment->sequence_number + 1U;

            connection->state =
                TCP_STATE_ESTABLISHED;

            connection->has_retransmit_segment =
                0;

            connection->retransmit_count =
                0;

            return 1;
        }

        return 0;
    }

    if (
        connection->state ==
        TCP_STATE_ESTABLISHED ||
        connection->state ==
        TCP_STATE_FIN_WAIT_1 ||
        connection->state ==
        TCP_STATE_FIN_WAIT_2
    ) {
        if (
            segment->payload_len > 0
        ) {
            if (
                segment->sequence_number ==
                connection->receive_next
            ) {
                connection->receive_next +=
                    (uint32_t)segment->payload_len;
            }
        }

        if (
            (segment->flags & TCP_FLAG_FIN) != 0
        ) {
            uint32_t fin_sequence =
                segment->sequence_number +
                (uint32_t)segment->payload_len;

            if (
                fin_sequence ==
                connection->receive_next
            ) {
                connection->receive_next++;

                if (
                    connection->state ==
                    TCP_STATE_ESTABLISHED
                ) {
                    connection->state =
                        TCP_STATE_CLOSE_WAIT;
                } else {
                    connection->state =
                        TCP_STATE_TIME_WAIT;
                }
            }
        }

        if (
            connection->state ==
                TCP_STATE_FIN_WAIT_1 &&
            connection->send_unacknowledged ==
                connection->send_next
        ) {
            connection->state =
                TCP_STATE_FIN_WAIT_2;
        }
    }

    return 0;
}

int tcp_connection_build_ack(
    const tcp_connection_t *connection,
    tcp_segment_t *segment,
    uint16_t window
)
{
    if (
        connection == NULL ||
        segment == NULL
    ) {
        return -1;
    }

    return tcp_build(
        segment,
        connection->local_port,
        connection->remote_port,
        connection->send_next,
        connection->receive_next,
        TCP_FLAG_ACK,
        window,
        NULL,
        0
    );
}

int tcp_connection_build_data(
    tcp_connection_t *connection,
    tcp_segment_t *segment,
    const uint8_t *payload,
    size_t payload_len,
    uint16_t window
)
{
    if (
        connection == NULL ||
        segment == NULL ||
        payload == NULL ||
        payload_len == 0 ||
        connection->state !=
            TCP_STATE_ESTABLISHED
    ) {
        return -1;
    }

    if (
        tcp_build(
            segment,
            connection->local_port,
            connection->remote_port,
            connection->send_next,
            connection->receive_next,
            TCP_FLAG_PSH |
            TCP_FLAG_ACK,
            window,
            payload,
            payload_len
        ) != 0
    ) {
        return -1;
    }

    connection->send_unacknowledged =
        connection->send_next;

    connection->send_next +=
        (uint32_t)payload_len;

    remember_for_retransmission(
        connection,
        segment
    );

    return 0;
}

int tcp_connection_build_fin(
    tcp_connection_t *connection,
    tcp_segment_t *segment,
    uint16_t window
)
{
    if (
        connection == NULL ||
        segment == NULL
    ) {
        return -1;
    }

    if (
        connection->state !=
            TCP_STATE_ESTABLISHED &&
        connection->state !=
            TCP_STATE_CLOSE_WAIT
    ) {
        return -1;
    }

    if (
        tcp_build(
            segment,
            connection->local_port,
            connection->remote_port,
            connection->send_next,
            connection->receive_next,
            TCP_FLAG_FIN |
            TCP_FLAG_ACK,
            window,
            NULL,
            0
        ) != 0
    ) {
        return -1;
    }

    connection->send_unacknowledged =
        connection->send_next;

    connection->send_next++;

    if (
        connection->state ==
        TCP_STATE_CLOSE_WAIT
    ) {
        connection->state =
            TCP_STATE_LAST_ACK;
    } else {
        connection->state =
            TCP_STATE_FIN_WAIT_1;
    }

    remember_for_retransmission(
        connection,
        segment
    );

    return 0;
}

int tcp_connection_tick(
    tcp_connection_t *connection,
    uint32_t elapsed_ms,
    tcp_segment_t *retransmit_segment
)
{
    if (
        connection == NULL ||
        retransmit_segment == NULL
    ) {
        return -1;
    }

    if (
        !connection->has_retransmit_segment
    ) {
        return 0;
    }

    connection->retransmit_elapsed_ms +=
        elapsed_ms;

    if (
        connection->retransmit_elapsed_ms <
        connection->retransmit_timeout_ms
    ) {
        return 0;
    }

    if (
        connection->retransmit_count >=
        connection->retransmit_limit
    ) {
        connection->state =
            TCP_STATE_RESET;

        connection->has_retransmit_segment =
            0;

        return -1;
    }

    *retransmit_segment =
        connection->last_segment;

    connection->retransmit_count++;

    connection->retransmit_elapsed_ms =
        0;

    /*
     * Basic exponential backoff.
     */
    if (
        connection->retransmit_timeout_ms <
        16000U
    ) {
        connection->retransmit_timeout_ms *=
            2U;
    }

    return 1;
}

const char *tcp_connection_state_name(
    tcp_connection_state_t state
)
{
    switch (state) {
        case TCP_STATE_CLOSED:
            return "CLOSED";

        case TCP_STATE_SYN_SENT:
            return "SYN-SENT";

        case TCP_STATE_ESTABLISHED:
            return "ESTABLISHED";

        case TCP_STATE_FIN_WAIT_1:
            return "FIN-WAIT-1";

        case TCP_STATE_FIN_WAIT_2:
            return "FIN-WAIT-2";

        case TCP_STATE_CLOSE_WAIT:
            return "CLOSE-WAIT";

        case TCP_STATE_LAST_ACK:
            return "LAST-ACK";

        case TCP_STATE_TIME_WAIT:
            return "TIME-WAIT";

        case TCP_STATE_RESET:
            return "RESET";

        default:
            return "UNKNOWN";
    }
}
