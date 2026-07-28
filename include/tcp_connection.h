#ifndef BLACKTERM_TCP_CONNECTION_H
#define BLACKTERM_TCP_CONNECTION_H

#include "tcp.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Reassembly limits.
 *
 * NETSTACK currently operates over Ethernet-sized traffic, so 2048 bytes
 * is comfortably larger than a normal TCP payload on the current path.
 *
 * These bounds also prevent an attacker or malformed peer from causing
 * unbounded userspace memory consumption.
 */
#define TCP_REASSEMBLY_SLOT_COUNT 16
#define TCP_REASSEMBLY_SLOT_DATA_LEN 2048
#define TCP_RECEIVE_READY_CAPACITY 32768

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
    int used;

    uint32_t sequence_number;

    size_t payload_len;

    uint8_t payload[
        TCP_REASSEMBLY_SLOT_DATA_LEN
    ];
} tcp_reassembly_slot_t;

typedef struct {
    tcp_connection_state_t state;

    uint16_t local_port;
    uint16_t remote_port;

    uint32_t send_unacknowledged;
    uint32_t send_next;

    /*
     * First sequence number not yet received contiguously.
     */
    uint32_t receive_next;

    uint16_t remote_window;

    /*
     * Outbound retransmission state.
     */
    uint32_t retransmit_timeout_ms;
    uint32_t retransmit_elapsed_ms;

    unsigned int retransmit_count;
    unsigned int retransmit_limit;

    tcp_segment_t last_segment;

    int has_retransmit_segment;

    /*
     * Receive reassembly queue.
     *
     * Future TCP segments live here until all sequence-space bytes
     * before them have arrived.
     */
    tcp_reassembly_slot_t reassembly[
        TCP_REASSEMBLY_SLOT_COUNT
    ];

    size_t reassembly_count;

    /*
     * Contiguous bytes ready for the application.
     *
     * tcp_connection_read() drains this buffer.
     */
    uint8_t receive_ready[
        TCP_RECEIVE_READY_CAPACITY
    ];

    size_t receive_ready_len;

    /*
     * FIN may arrive before missing payload.
     *
     * We remember its sequence number and consume it only once
     * receive_next reaches the FIN position.
     */
    int pending_fin;

    uint32_t pending_fin_sequence;
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

/*
 * Feed one received TCP segment into the connection engine.
 *
 * Return values:
 *
 *   1  handshake completed
 *   0  segment processed
 *  -1  invalid argument / invalid connection segment
 *  -2  receive/reassembly capacity exhausted
 */
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

/*
 * Copy contiguous received TCP application data out of the connection.
 *
 * Returns number of bytes copied.
 */
size_t tcp_connection_read(
    tcp_connection_t *connection,
    uint8_t *buffer,
    size_t buffer_len
);

/*
 * Number of contiguous application bytes currently ready to read.
 */
size_t tcp_connection_readable(
    const tcp_connection_t *connection
);

/*
 * Number of future/out-of-order segments currently buffered.
 */
size_t tcp_connection_reassembly_count(
    const tcp_connection_t *connection
);

const char *tcp_connection_state_name(
    tcp_connection_state_t state
);

#endif
