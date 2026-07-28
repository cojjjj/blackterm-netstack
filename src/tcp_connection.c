#include "tcp_connection.h"

#include <stdint.h>
#include <string.h>

#define TCP_DEFAULT_RTO_MS 1000U
#define TCP_DEFAULT_RETRANSMIT_LIMIT 5U
#define TCP_MAX_RTO_MS 16000U

/*
 * TCP sequence numbers wrap at 2^32.
 *
 * These helpers compare sequence numbers using signed distance,
 * which is the standard style for TCP sequence-space comparisons
 * as long as compared distances remain below 2^31.
 */
static int seq_lt(
    uint32_t a,
    uint32_t b
)
{
    return (int32_t)(a - b) < 0;
}

static int seq_le(
    uint32_t a,
    uint32_t b
)
{
    return (int32_t)(a - b) <= 0;
}

static int seq_gt(
    uint32_t a,
    uint32_t b
)
{
    return (int32_t)(a - b) > 0;
}

static int seq_ge(
    uint32_t a,
    uint32_t b
)
{
    return (int32_t)(a - b) >= 0;
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

static void clear_reassembly(
    tcp_connection_t *connection
)
{
    memset(
        connection->reassembly,
        0,
        sizeof(connection->reassembly)
    );

    connection->reassembly_count =
        0;

    connection->receive_ready_len =
        0;

    connection->pending_fin =
        0;

    connection->pending_fin_sequence =
        0;
}

static int ready_append(
    tcp_connection_t *connection,
    const uint8_t *data,
    size_t data_len
)
{
    if (
        connection == NULL ||
        data == NULL
    ) {
        return -1;
    }

    if (data_len == 0) {
        return 0;
    }

    if (
        connection->receive_ready_len >
        TCP_RECEIVE_READY_CAPACITY
    ) {
        return -1;
    }

    if (
        data_len >
        TCP_RECEIVE_READY_CAPACITY -
        connection->receive_ready_len
    ) {
        return -1;
    }

    memcpy(
        connection->receive_ready +
        connection->receive_ready_len,
        data,
        data_len
    );

    connection->receive_ready_len +=
        data_len;

    return 0;
}

static int find_free_reassembly_slot(
    const tcp_connection_t *connection
)
{
    for (
        size_t i = 0;
        i < TCP_REASSEMBLY_SLOT_COUNT;
        i++
    ) {
        if (
            !connection->reassembly[i].used
        ) {
            return (int)i;
        }
    }

    return -1;
}

/*
 * Return 1 when the new segment range is fully contained inside
 * an already buffered range.
 */
static int range_already_buffered(
    const tcp_connection_t *connection,
    uint32_t start,
    uint32_t end
)
{
    for (
        size_t i = 0;
        i < TCP_REASSEMBLY_SLOT_COUNT;
        i++
    ) {
        const tcp_reassembly_slot_t *slot =
            &connection->reassembly[i];

        if (!slot->used) {
            continue;
        }

        uint32_t slot_start =
            slot->sequence_number;

        uint32_t slot_end =
            slot_start +
            (uint32_t)slot->payload_len;

        if (
            seq_ge(start, slot_start) &&
            seq_le(end, slot_end)
        ) {
            return 1;
        }
    }

    return 0;
}

/*
 * Buffer a future segment.
 *
 * This initial reassembly implementation stores each segment as one
 * bounded queue entry. Overlapping future segments are allowed unless
 * the new segment is completely contained inside existing buffered data.
 *
 * Once the gap closes, promotion logic clips overlap before delivery.
 */
static int buffer_future_payload(
    tcp_connection_t *connection,
    uint32_t sequence_number,
    const uint8_t *payload,
    size_t payload_len
)
{
    if (
        connection == NULL ||
        payload == NULL ||
        payload_len == 0
    ) {
        return -1;
    }

    if (
        payload_len >
        TCP_REASSEMBLY_SLOT_DATA_LEN
    ) {
        return -1;
    }

    uint32_t end =
        sequence_number +
        (uint32_t)payload_len;

    if (
        range_already_buffered(
            connection,
            sequence_number,
            end
        )
    ) {
        return 0;
    }

    int slot_index =
        find_free_reassembly_slot(
            connection
        );

    if (slot_index < 0) {
        return -1;
    }

    tcp_reassembly_slot_t *slot =
        &connection->reassembly[
            (size_t)slot_index
        ];

    slot->used =
        1;

    slot->sequence_number =
        sequence_number;

    slot->payload_len =
        payload_len;

    memcpy(
        slot->payload,
        payload,
        payload_len
    );

    connection->reassembly_count++;

    return 0;
}

static void remove_reassembly_slot(
    tcp_connection_t *connection,
    size_t index
)
{
    if (
        connection == NULL ||
        index >= TCP_REASSEMBLY_SLOT_COUNT ||
        !connection->reassembly[index].used
    ) {
        return;
    }

    memset(
        &connection->reassembly[index],
        0,
        sizeof(connection->reassembly[index])
    );

    if (
        connection->reassembly_count > 0
    ) {
        connection->reassembly_count--;
    }
}

static void consume_pending_fin(
    tcp_connection_t *connection
)
{
    if (
        connection == NULL ||
        !connection->pending_fin
    ) {
        return;
    }

    if (
        connection->pending_fin_sequence !=
        connection->receive_next
    ) {
        return;
    }

    connection->receive_next++;

    connection->pending_fin =
        0;

    if (
        connection->state ==
        TCP_STATE_ESTABLISHED
    ) {
        connection->state =
            TCP_STATE_CLOSE_WAIT;
    } else if (
        connection->state ==
            TCP_STATE_FIN_WAIT_1 ||
        connection->state ==
            TCP_STATE_FIN_WAIT_2
    ) {
        connection->state =
            TCP_STATE_TIME_WAIT;
    }
}

/*
 * Promote every buffered range that has become contiguous.
 *
 * We repeatedly scan because consuming one segment may make another
 * buffered segment immediately consumable.
 */
static int promote_reassembly(
    tcp_connection_t *connection
)
{
    int progress = 1;

    while (progress) {
        progress = 0;

        for (
            size_t i = 0;
            i < TCP_REASSEMBLY_SLOT_COUNT;
            i++
        ) {
            tcp_reassembly_slot_t *slot =
                &connection->reassembly[i];

            if (!slot->used) {
                continue;
            }

            uint32_t start =
                slot->sequence_number;

            uint32_t end =
                start +
                (uint32_t)slot->payload_len;

            /*
             * Already fully received.
             */
            if (
                seq_le(
                    end,
                    connection->receive_next
                )
            ) {
                remove_reassembly_slot(
                    connection,
                    i
                );

                progress = 1;

                continue;
            }

            /*
             * Still begins in the future.
             */
            if (
                seq_gt(
                    start,
                    connection->receive_next
                )
            ) {
                continue;
            }

            /*
             * This slot begins at or before receive_next and extends
             * beyond it. Clip the overlapping prefix and deliver only
             * bytes not previously received.
             */
            uint32_t overlap =
                connection->receive_next -
                start;

            if (
                overlap >
                slot->payload_len
            ) {
                continue;
            }

            size_t payload_offset =
                (size_t)overlap;

            size_t new_len =
                slot->payload_len -
                payload_offset;

            if (
                new_len > 0 &&
                ready_append(
                    connection,
                    slot->payload +
                    payload_offset,
                    new_len
                ) != 0
            ) {
                return -1;
            }

            connection->receive_next +=
                (uint32_t)new_len;

            remove_reassembly_slot(
                connection,
                i
            );

            progress = 1;
        }
    }

    consume_pending_fin(
        connection
    );

    return 0;
}

static int process_payload(
    tcp_connection_t *connection,
    const tcp_segment_t *segment
)
{
    if (
        segment->payload_len == 0
    ) {
        return 0;
    }

    uint32_t start =
        segment->sequence_number;

    uint32_t end =
        start +
        (uint32_t)segment->payload_len;

    /*
     * Entire payload is behind receive_next.
     *
     * This is a duplicate retransmission.
     */
    if (
        seq_le(
            end,
            connection->receive_next
        )
    ) {
        return 0;
    }

    /*
     * Segment begins after a gap.
     *
     * Save it for later.
     */
    if (
        seq_gt(
            start,
            connection->receive_next
        )
    ) {
        if (
            buffer_future_payload(
                connection,
                start,
                segment->payload,
                segment->payload_len
            ) != 0
        ) {
            return -1;
        }

        return 0;
    }

    /*
     * Segment is contiguous or partially overlaps already-received
     * bytes.
     *
     * Example:
     *
     * receive_next = 1005
     *
     * segment = 1000..1010
     *
     * bytes 1000..1004 are duplicates.
     * bytes 1005..1009 are new.
     */
    uint32_t overlap =
        connection->receive_next -
        start;

    if (
        overlap >
        segment->payload_len
    ) {
        return 0;
    }

    size_t payload_offset =
        (size_t)overlap;

    size_t new_len =
        segment->payload_len -
        payload_offset;

    if (
        new_len > 0 &&
        ready_append(
            connection,
            segment->payload +
            payload_offset,
            new_len
        ) != 0
    ) {
        return -1;
    }

    connection->receive_next +=
        (uint32_t)new_len;

    /*
     * Filling this range may close one or several buffered gaps.
     */
    return promote_reassembly(
        connection
    );
}

static void process_fin(
    tcp_connection_t *connection,
    const tcp_segment_t *segment
)
{
    if (
        (segment->flags &
        TCP_FLAG_FIN) == 0
    ) {
        return;
    }

    uint32_t fin_sequence =
        segment->sequence_number +
        (uint32_t)segment->payload_len;

    /*
     * FIN is exactly next in sequence space.
     */
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
        } else if (
            connection->state ==
                TCP_STATE_FIN_WAIT_1 ||
            connection->state ==
                TCP_STATE_FIN_WAIT_2
        ) {
            connection->state =
                TCP_STATE_TIME_WAIT;
        }

        return;
    }

    /*
     * FIN is ahead of a receive gap.
     */
    if (
        seq_gt(
            fin_sequence,
            connection->receive_next
        )
    ) {
        if (
            !connection->pending_fin ||
            seq_lt(
                fin_sequence,
                connection->pending_fin_sequence
            )
        ) {
            connection->pending_fin =
                1;

            connection->pending_fin_sequence =
                fin_sequence;
        }
    }
}

void tcp_connection_init(
    tcp_connection_t *connection,
    uint16_t local_port,
    uint16_t remote_port,
    uint32_t initial_sequence
)
{
    if (
        connection == NULL
    ) {
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

    clear_reassembly(
        connection
    );
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
        connection->state !=
            TCP_STATE_CLOSED
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

    /*
     * RST immediately terminates the userspace connection.
     */
    if (
        (segment->flags &
        TCP_FLAG_RST) != 0
    ) {
        connection->state =
            TCP_STATE_RESET;

        connection->has_retransmit_segment =
            0;

        clear_reassembly(
            connection
        );

        return 0;
    }

    /*
     * ACK processing.
     */
    if (
        (segment->flags &
        TCP_FLAG_ACK) != 0
    ) {
        if (
            seq_gt(
                segment->acknowledgment_number,
                connection->send_unacknowledged
            ) &&
            seq_le(
                segment->acknowledgment_number,
                connection->send_next
            )
        ) {
            connection->send_unacknowledged =
                segment->acknowledgment_number;

            connection->retransmit_elapsed_ms =
                0;

            connection->retransmit_count =
                0;

            /*
             * Current outbound implementation tracks a single
             * outstanding retransmittable segment.
             */
            if (
                connection->send_unacknowledged ==
                connection->send_next
            ) {
                connection->has_retransmit_segment =
                    0;

                connection->retransmit_timeout_ms =
                    TCP_DEFAULT_RTO_MS;
            }
        }
    }

    connection->remote_window =
        segment->window_size;

    /*
     * Handshake.
     */
    if (
        connection->state ==
        TCP_STATE_SYN_SENT
    ) {
        if (
            (segment->flags &
            (
                TCP_FLAG_SYN |
                TCP_FLAG_ACK
            )) ==
            (
                TCP_FLAG_SYN |
                TCP_FLAG_ACK
            )
        ) {
            if (
                segment->acknowledgment_number !=
                connection->send_next
            ) {
                return -1;
            }

            connection->receive_next =
                segment->sequence_number +
                1U;

            connection->state =
                TCP_STATE_ESTABLISHED;

            connection->has_retransmit_segment =
                0;

            connection->retransmit_count =
                0;

            connection->retransmit_elapsed_ms =
                0;

            connection->retransmit_timeout_ms =
                TCP_DEFAULT_RTO_MS;

            return 1;
        }

        return 0;
    }

    if (
        connection->state !=
            TCP_STATE_ESTABLISHED &&
        connection->state !=
            TCP_STATE_FIN_WAIT_1 &&
        connection->state !=
            TCP_STATE_FIN_WAIT_2 &&
        connection->state !=
            TCP_STATE_CLOSE_WAIT &&
        connection->state !=
            TCP_STATE_LAST_ACK
    ) {
        return 0;
    }

    /*
     * Application payload reassembly.
     */
    if (
        process_payload(
            connection,
            segment
        ) != 0
    ) {
        return -2;
    }

    /*
     * FIN processing happens after payload processing because FIN's
     * sequence position occurs after the segment payload.
     */
    process_fin(
        connection,
        segment
    );

    /*
     * A previously buffered FIN may now have become contiguous.
     */
    consume_pending_fin(
        connection
    );

    /*
     * Active close:
     *
     * our FIN has now been acknowledged.
     */
    if (
        connection->state ==
            TCP_STATE_FIN_WAIT_1 &&
        connection->send_unacknowledged ==
            connection->send_next
    ) {
        connection->state =
            TCP_STATE_FIN_WAIT_2;
    }

    /*
     * Passive close:
     *
     * our FIN in LAST-ACK has now been acknowledged.
     */
    if (
        connection->state ==
            TCP_STATE_LAST_ACK &&
        connection->send_unacknowledged ==
            connection->send_next
    ) {
        connection->state =
            TCP_STATE_CLOSED;

        connection->has_retransmit_segment =
            0;
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

    /*
     * Avoid uint32_t timer wrap.
     */
    if (
        elapsed_ms >
        UINT32_MAX -
        connection->retransmit_elapsed_ms
    ) {
        connection->retransmit_elapsed_ms =
            UINT32_MAX;
    } else {
        connection->retransmit_elapsed_ms +=
            elapsed_ms;
    }

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

    if (
        connection->retransmit_timeout_ms <
        TCP_MAX_RTO_MS
    ) {
        uint32_t doubled =
            connection->retransmit_timeout_ms *
            2U;

        if (
            doubled >
            TCP_MAX_RTO_MS
        ) {
            doubled =
                TCP_MAX_RTO_MS;
        }

        connection->retransmit_timeout_ms =
            doubled;
    }

    return 1;
}

size_t tcp_connection_read(
    tcp_connection_t *connection,
    uint8_t *buffer,
    size_t buffer_len
)
{
    if (
        connection == NULL ||
        buffer == NULL ||
        buffer_len == 0 ||
        connection->receive_ready_len == 0
    ) {
        return 0;
    }

    size_t copy_len =
        connection->receive_ready_len;

    if (
        copy_len >
        buffer_len
    ) {
        copy_len =
            buffer_len;
    }

    memcpy(
        buffer,
        connection->receive_ready,
        copy_len
    );

    size_t remaining =
        connection->receive_ready_len -
        copy_len;

    if (
        remaining > 0
    ) {
        memmove(
            connection->receive_ready,
            connection->receive_ready +
            copy_len,
            remaining
        );
    }

    connection->receive_ready_len =
        remaining;

    return copy_len;
}

size_t tcp_connection_readable(
    const tcp_connection_t *connection
)
{
    if (
        connection == NULL
    ) {
        return 0;
    }

    return
        connection->receive_ready_len;
}

size_t tcp_connection_reassembly_count(
    const tcp_connection_t *connection
)
{
    if (
        connection == NULL
    ) {
        return 0;
    }

    return
        connection->reassembly_count;
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
