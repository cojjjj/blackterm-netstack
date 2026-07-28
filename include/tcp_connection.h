#ifndef BLACKTERM_TCP_CONNECTION_H
#define BLACKTERM_TCP_CONNECTION_H

#include "tcp.h"

#include <stddef.h>
#include <stdint.h>

typedef enum {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_RESET
} tcp_connection_state_t;

typedef struct {
    tcp_connection_state_t state;

    uint16_t local_port;
    uint16_t remote_port;

    uint32_t send_unacknowledged;
    uint32_t send_next;

    uint32_t receive_next;

    uint16_t remote_window;

    uint32_t retransmit_timeout_ms;
    uint32_t retransmit_elapsed_ms;
    unsigned int retransmit_count;
    unsigned int retransmit_limit;

    tcp_segment_t last_segment;

    int has_retransmit_segment;
} tcp_connection_t;

void tcp_connection_init(
    tcp_connection_t *connection,
    uint16_t local_port,
    uint16_t remote_port,
    uint32_t initial_sequence
);

int tcp_connection_build_syn(
    tcp_connection_t *connection,
    tcp_segment_t *segment,
    uint16_t window
);

int tcp_connection_on_segment(
    tcp_connection_t *connection,
    const tcp_segment_t *segment
);

int tcp_connection_build_ack(
    const tcp_connection_t *connection,
    tcp_segment_t *segment,
    uint16_t window
);

int tcp_connection_build_data(
    tcp_connection_t *connection,
    tcp_segment_t *segment,
    const uint8_t *payload,
    size_t payload_len,
    uint16_t window
);

int tcp_connection_build_fin(
    tcp_connection_t *connection,
    tcp_segment_t *segment,
    uint16_t window
);

int tcp_connection_tick(
    tcp_connection_t *connection,
    uint32_t elapsed_ms,
    tcp_segment_t *retransmit_segment
);

const char *tcp_connection_state_name(
    tcp_connection_state_t state
);

#endif
