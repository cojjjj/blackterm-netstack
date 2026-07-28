#define _POSIX_C_SOURCE 200809L

#include "arp.h"
#include "ethernet.h"
#include "http.h"
#include "ipv4.h"
#include "netdev.h"
#include "tcp.h"
#include "tcp_connection.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RECEIVE_BUFFER_SIZE 2048

#define ARP_TIMEOUT_MS 3000
#define TCP_POLL_MS 250
#define TCP_CONNECT_TIMEOUT_MS 10000
#define HTTP_TIMEOUT_MS 15000

#define HTTP_SOURCE_PORT 40001
#define HTTP_DESTINATION_PORT 80

#define TCP_WINDOW_SIZE 64240

#define HTTP_RESPONSE_INITIAL_CAPACITY 8192
#define HTTP_RESPONSE_MAX_SIZE (1024U * 1024U)

#define TCP_APP_READ_BUFFER 4096

static void print_ipv4(
    const uint8_t ip[IPV4_ADDR_LEN]
)
{
    printf(
        "%u.%u.%u.%u",
        (unsigned int)ip[0],
        (unsigned int)ip[1],
        (unsigned int)ip[2],
        (unsigned int)ip[3]
    );
}

static void print_mac(
    const uint8_t mac[ETHERNET_ADDR_LEN]
)
{
    printf(
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
}

static double elapsed_ms(
    const struct timespec *start,
    const struct timespec *end
)
{
    return
        ((double)(
            end->tv_sec -
            start->tv_sec
        ) * 1000.0) +
        ((double)(
            end->tv_nsec -
            start->tv_nsec
        ) / 1000000.0);
}

static uint32_t generate_isn(void)
{
    struct timespec now;

    if (
        clock_gettime(
            CLOCK_MONOTONIC,
            &now
        ) != 0
    ) {
        return 0x42424242U;
    }

    uint64_t value =
        ((uint64_t)now.tv_sec << 32) ^
        (uint64_t)now.tv_nsec;

    value ^= value >> 33;

    value *= UINT64_C(
        0xff51afd7ed558ccd
    );

    value ^= value >> 33;

    return (uint32_t)value;
}

static int resolve_arp(
    netdev_t *dev,
    const uint8_t next_hop_ip[IPV4_ADDR_LEN],
    uint8_t next_hop_mac[ETHERNET_ADDR_LEN]
)
{
    arp_packet_t request;

    if (
        arp_build_request(
            &request,
            dev->mac,
            dev->ipv4,
            next_hop_ip
        ) != 0
    ) {
        return -1;
    }

    uint8_t arp_bytes[
        ARP_PACKET_LEN
    ];

    size_t arp_len =
        arp_serialize(
            &request,
            arp_bytes,
            sizeof(arp_bytes)
        );

    if (arp_len == 0) {
        return -1;
    }

    ethernet_frame_t frame = {0};

    memset(
        frame.destination,
        0xFF,
        ETHERNET_ADDR_LEN
    );

    memcpy(
        frame.source,
        dev->mac,
        ETHERNET_ADDR_LEN
    );

    frame.ethertype =
        ETHERNET_TYPE_ARP;

    memcpy(
        frame.payload,
        arp_bytes,
        arp_len
    );

    frame.payload_len =
        arp_len;

    uint8_t frame_bytes[
        ETHERNET_MAX_FRAME_LEN
    ];

    size_t frame_len =
        ethernet_serialize(
            &frame,
            frame_bytes,
            sizeof(frame_bytes)
        );

    if (frame_len == 0) {
        return -1;
    }

    if (
        netdev_send(
            dev,
            frame_bytes,
            frame_len
        ) < 0
    ) {
        return -1;
    }

    printf("ARP  who-has ");
    print_ipv4(next_hop_ip);
    printf("\n");

    struct timespec start;

    if (
        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        ) != 0
    ) {
        return -1;
    }

    uint8_t receive_buffer[
        RECEIVE_BUFFER_SIZE
    ];

    for (;;) {
        struct timespec now;

        if (
            clock_gettime(
                CLOCK_MONOTONIC,
                &now
            ) != 0
        ) {
            return -1;
        }

        if (
            elapsed_ms(
                &start,
                &now
            ) >
            ARP_TIMEOUT_MS
        ) {
            fprintf(
                stderr,
                "ARP request timed out.\n"
            );

            return -1;
        }

        long received =
            netdev_receive(
                dev,
                receive_buffer,
                sizeof(receive_buffer),
                TCP_POLL_MS
            );

        if (received < 0) {
            return -1;
        }

        if (received == 0) {
            continue;
        }

        ethernet_frame_t ethernet;

        if (
            ethernet_parse(
                receive_buffer,
                (size_t)received,
                &ethernet
            ) != 0
        ) {
            continue;
        }

        if (
            ethernet.ethertype !=
            ETHERNET_TYPE_ARP
        ) {
            continue;
        }

        arp_packet_t reply;

        if (
            arp_parse(
                ethernet.payload,
                ethernet.payload_len,
                &reply
            ) != 0
        ) {
            continue;
        }

        if (
            reply.opcode !=
            ARP_OPCODE_REPLY
        ) {
            continue;
        }

        if (
            memcmp(
                reply.sender_ip,
                next_hop_ip,
                IPV4_ADDR_LEN
            ) != 0
        ) {
            continue;
        }

        if (
            memcmp(
                reply.target_ip,
                dev->ipv4,
                IPV4_ADDR_LEN
            ) != 0
        ) {
            continue;
        }

        memcpy(
            next_hop_mac,
            reply.sender_mac,
            ETHERNET_ADDR_LEN
        );

        printf("ARP  ");
        print_ipv4(next_hop_ip);
        printf(" is-at ");
        print_mac(next_hop_mac);
        printf("\n");

        return 0;
    }
}

static int send_tcp_segment(
    netdev_t *dev,
    const uint8_t target_ip[IPV4_ADDR_LEN],
    const uint8_t next_hop_mac[ETHERNET_ADDR_LEN],
    const tcp_segment_t *tcp
)
{
    if (
        dev == NULL ||
        target_ip == NULL ||
        next_hop_mac == NULL ||
        tcp == NULL
    ) {
        return -1;
    }

    uint8_t tcp_bytes[
        ETHERNET_MAX_PAYLOAD
    ];

    size_t tcp_len =
        tcp_serialize_ipv4(
            tcp,
            dev->ipv4,
            target_ip,
            tcp_bytes,
            sizeof(tcp_bytes)
        );

    if (tcp_len == 0) {
        return -1;
    }

    ipv4_packet_t ip;

    if (
        ipv4_build(
            &ip,
            dev->ipv4,
            target_ip,
            IPV4_PROTOCOL_TCP,
            tcp_bytes,
            tcp_len,
            64,
            0x4854
        ) != 0
    ) {
        return -1;
    }

    uint8_t ip_bytes[
        ETHERNET_MAX_PAYLOAD
    ];

    size_t ip_len =
        ipv4_serialize(
            &ip,
            ip_bytes,
            sizeof(ip_bytes)
        );

    if (ip_len == 0) {
        return -1;
    }

    ethernet_frame_t ethernet = {0};

    memcpy(
        ethernet.destination,
        next_hop_mac,
        ETHERNET_ADDR_LEN
    );

    memcpy(
        ethernet.source,
        dev->mac,
        ETHERNET_ADDR_LEN
    );

    ethernet.ethertype =
        ETHERNET_TYPE_IPV4;

    memcpy(
        ethernet.payload,
        ip_bytes,
        ip_len
    );

    ethernet.payload_len =
        ip_len;

    uint8_t frame[
        ETHERNET_MAX_FRAME_LEN
    ];

    size_t frame_len =
        ethernet_serialize(
            &ethernet,
            frame,
            sizeof(frame)
        );

    if (frame_len == 0) {
        return -1;
    }

    return
        netdev_send(
            dev,
            frame,
            frame_len
        ) < 0
            ? -1
            : 0;
}

static int receive_tcp_segment(
    netdev_t *dev,
    const uint8_t target_ip[IPV4_ADDR_LEN],
    tcp_segment_t *tcp,
    int timeout_ms
)
{
    struct timespec start;

    if (
        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        ) != 0
    ) {
        return -1;
    }

    uint8_t receive_buffer[
        RECEIVE_BUFFER_SIZE
    ];

    for (;;) {
        struct timespec now;

        if (
            clock_gettime(
                CLOCK_MONOTONIC,
                &now
            ) != 0
        ) {
            return -1;
        }

        if (
            elapsed_ms(
                &start,
                &now
            ) >
            timeout_ms
        ) {
            return 0;
        }

        long received =
            netdev_receive(
                dev,
                receive_buffer,
                sizeof(receive_buffer),
                TCP_POLL_MS
            );

        if (received < 0) {
            return -1;
        }

        if (received == 0) {
            continue;
        }

        ethernet_frame_t ethernet;

        if (
            ethernet_parse(
                receive_buffer,
                (size_t)received,
                &ethernet
            ) != 0
        ) {
            continue;
        }

        if (
            ethernet.ethertype !=
            ETHERNET_TYPE_IPV4
        ) {
            continue;
        }

        ipv4_packet_t ip;

        if (
            ipv4_parse(
                ethernet.payload,
                ethernet.payload_len,
                &ip
            ) != 0
        ) {
            continue;
        }

        if (
            ip.protocol !=
            IPV4_PROTOCOL_TCP
        ) {
            continue;
        }

        if (
            memcmp(
                ip.source_ip,
                target_ip,
                IPV4_ADDR_LEN
            ) != 0
        ) {
            continue;
        }

        if (
            memcmp(
                ip.destination_ip,
                dev->ipv4,
                IPV4_ADDR_LEN
            ) != 0
        ) {
            continue;
        }

        if (
            !tcp_checksum_ipv4_valid(
                ip.source_ip,
                ip.destination_ip,
                ip.payload,
                ip.payload_len
            )
        ) {
            continue;
        }

        tcp_segment_t parsed;

        if (
            tcp_parse(
                ip.payload,
                ip.payload_len,
                &parsed
            ) != 0
        ) {
            continue;
        }

        if (
            parsed.source_port !=
            HTTP_DESTINATION_PORT ||
            parsed.destination_port !=
            HTTP_SOURCE_PORT
        ) {
            continue;
        }

        *tcp =
            parsed;

        return 1;
    }
}

static int send_connection_ack(
    netdev_t *dev,
    const uint8_t target_ip[IPV4_ADDR_LEN],
    const uint8_t next_hop_mac[ETHERNET_ADDR_LEN],
    const tcp_connection_t *connection
)
{
    tcp_segment_t ack;

    if (
        tcp_connection_build_ack(
            connection,
            &ack,
            TCP_WINDOW_SIZE
        ) != 0
    ) {
        return -1;
    }

    return send_tcp_segment(
        dev,
        target_ip,
        next_hop_mac,
        &ack
    );
}

static int append_response(
    char **buffer,
    size_t *length,
    size_t *capacity,
    const uint8_t *data,
    size_t data_len
)
{
    if (
        buffer == NULL ||
        length == NULL ||
        capacity == NULL ||
        data == NULL
    ) {
        return -1;
    }

    if (data_len == 0) {
        return 0;
    }

    if (
        *length >=
        HTTP_RESPONSE_MAX_SIZE
    ) {
        return -1;
    }

    if (
        data_len >
        HTTP_RESPONSE_MAX_SIZE -
        *length -
        1U
    ) {
        return -1;
    }

    size_t required =
        *length +
        data_len +
        1U;

    if (
        required >
        *capacity
    ) {
        size_t new_capacity =
            *capacity;

        if (
            new_capacity == 0
        ) {
            new_capacity =
                HTTP_RESPONSE_INITIAL_CAPACITY;
        }

        while (
            new_capacity <
            required
        ) {
            if (
                new_capacity >=
                HTTP_RESPONSE_MAX_SIZE / 2U
            ) {
                new_capacity =
                    HTTP_RESPONSE_MAX_SIZE;
            } else {
                new_capacity *= 2U;
            }

            if (
                new_capacity <
                    required &&
                new_capacity ==
                    HTTP_RESPONSE_MAX_SIZE
            ) {
                return -1;
            }
        }

        char *new_buffer =
            realloc(
                *buffer,
                new_capacity
            );

        if (
            new_buffer ==
            NULL
        ) {
            return -1;
        }

        *buffer =
            new_buffer;

        *capacity =
            new_capacity;
    }

    memcpy(
        *buffer +
        *length,
        data,
        data_len
    );

    *length +=
        data_len;

    (*buffer)[*length] =
        '\0';

    return 0;
}

static int drain_tcp_application_data(
    tcp_connection_t *connection,
    char **response_data,
    size_t *response_len,
    size_t *response_capacity
)
{
    uint8_t buffer[
        TCP_APP_READ_BUFFER
    ];

    while (
        tcp_connection_readable(
            connection
        ) > 0
    ) {
        size_t read_len =
            tcp_connection_read(
                connection,
                buffer,
                sizeof(buffer)
            );

        if (
            read_len == 0
        ) {
            break;
        }

        if (
            append_response(
                response_data,
                response_len,
                response_capacity,
                buffer,
                read_len
            ) != 0
        ) {
            return -1;
        }

        printf(
            "TCP  DELIVER      bytes=%zu total=%zu ack=%u queued=%zu\n",
            read_len,
            *response_len,
            connection->receive_next,
            tcp_connection_reassembly_count(
                connection
            )
        );
    }

    return 0;
}

static int print_http_response(
    const char *response_data,
    size_t response_len
)
{
    http_response_t response;

    if (
        http_parse_response(
            response_data,
            response_len,
            &response
        ) != 0
    ) {
        fprintf(
            stderr,
            "Could not parse HTTP response.\n"
        );

        return -1;
    }

    int chunked =
        http_response_is_chunked(
            response_data,
            response.header_len
        );

    if (
        chunked < 0
    ) {
        return -1;
    }

    printf(
        "\nHTTP RESPONSE\n"
        "status: %d %s\n"
        "headers: %zu bytes\n",
        response.status_code,
        response.status_text,
        response.header_len
    );

    printf(
        "\n--- HEADERS ---\n"
    );

    fwrite(
        response_data,
        1,
        response.header_len,
        stdout
    );

    if (chunked) {
        size_t decoded_capacity =
            response.body_len +
            1U;

        char *decoded =
            malloc(
                decoded_capacity
            );

        if (
            decoded ==
            NULL
        ) {
            return -1;
        }

        size_t decoded_len =
            http_decode_chunked_body(
                response.body,
                response.body_len,
                decoded,
                decoded_capacity
            );

        if (
            decoded_len == 0 &&
            response.body_len > 5
        ) {
            fprintf(
                stderr,
                "Chunked body decoding failed.\n"
            );

            free(decoded);

            return -1;
        }

        printf(
            "\n--- BODY (chunked decoded) ---\n"
        );

        if (
            decoded_len > 0
        ) {
            fwrite(
                decoded,
                1,
                decoded_len,
                stdout
            );
        }

        printf(
            "\n\nraw body: %zu bytes\n"
            "decoded body: %zu bytes\n",
            response.body_len,
            decoded_len
        );

        free(decoded);
    } else {
        printf(
            "\n--- BODY ---\n"
        );

        if (
            response.body_len > 0
        ) {
            fwrite(
                response.body,
                1,
                response.body_len,
                stdout
            );
        }

        printf(
            "\n\nbody: %zu bytes\n",
            response.body_len
        );
    }

    return 0;
}

static int connect_tcp(
    netdev_t *dev,
    const uint8_t target_ip[IPV4_ADDR_LEN],
    const uint8_t next_hop_mac[ETHERNET_ADDR_LEN],
    tcp_connection_t *connection
)
{
    tcp_segment_t syn;

    if (
        tcp_connection_build_syn(
            connection,
            &syn,
            TCP_WINDOW_SIZE
        ) != 0
    ) {
        return -1;
    }

    printf(
        "TCP  %-12s seq=%u\n",
        tcp_connection_state_name(
            connection->state
        ),
        syn.sequence_number
    );

    if (
        send_tcp_segment(
            dev,
            target_ip,
            next_hop_mac,
            &syn
        ) != 0
    ) {
        return -1;
    }

    struct timespec start;

    if (
        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        ) != 0
    ) {
        return -1;
    }

    for (;;) {
        struct timespec now;

        if (
            clock_gettime(
                CLOCK_MONOTONIC,
                &now
            ) != 0
        ) {
            return -1;
        }

        if (
            elapsed_ms(
                &start,
                &now
            ) >
            TCP_CONNECT_TIMEOUT_MS
        ) {
            fprintf(
                stderr,
                "TCP connection timed out.\n"
            );

            return -1;
        }

        tcp_segment_t incoming;

        int result =
            receive_tcp_segment(
                dev,
                target_ip,
                &incoming,
                TCP_POLL_MS
            );

        if (
            result < 0
        ) {
            return -1;
        }

        if (
            result == 1
        ) {
            int state_result =
                tcp_connection_on_segment(
                    connection,
                    &incoming
                );

            if (
                state_result < 0
            ) {
                continue;
            }

            if (
                connection->state ==
                TCP_STATE_RESET
            ) {
                fprintf(
                    stderr,
                    "TCP connection reset.\n"
                );

                return -1;
            }

            if (
                connection->state ==
                TCP_STATE_ESTABLISHED
            ) {
                printf(
                    "TCP  SYN-ACK      seq=%u ack=%u\n",
                    incoming.sequence_number,
                    incoming.acknowledgment_number
                );

                if (
                    send_connection_ack(
                        dev,
                        target_ip,
                        next_hop_mac,
                        connection
                    ) != 0
                ) {
                    return -1;
                }

                printf(
                    "TCP  STATE        %s\n",
                    tcp_connection_state_name(
                        connection->state
                    )
                );

                return 0;
            }
        }

        tcp_segment_t retransmit;

        int retransmit_result =
            tcp_connection_tick(
                connection,
                TCP_POLL_MS,
                &retransmit
            );

        if (
            retransmit_result < 0
        ) {
            fprintf(
                stderr,
                "TCP retransmission limit reached.\n"
            );

            return -1;
        }

        if (
            retransmit_result == 1
        ) {
            printf(
                "TCP  RETRANSMIT   %s seq=%u retry=%u rto=%u ms\n",
                tcp_state_flag_name(
                    retransmit.flags
                ),
                retransmit.sequence_number,
                connection->retransmit_count,
                connection->retransmit_timeout_ms
            );

            if (
                send_tcp_segment(
                    dev,
                    target_ip,
                    next_hop_mac,
                    &retransmit
                ) != 0
            ) {
                return -1;
            }
        }
    }
}

static int run_http(
    netdev_t *dev,
    const uint8_t target_ip[IPV4_ADDR_LEN],
    const uint8_t next_hop_mac[ETHERNET_ADDR_LEN],
    const char *host,
    const char *path
)
{
    tcp_connection_t connection;

    tcp_connection_init(
        &connection,
        HTTP_SOURCE_PORT,
        HTTP_DESTINATION_PORT,
        generate_isn()
    );

    if (
        connect_tcp(
            dev,
            target_ip,
            next_hop_mac,
            &connection
        ) != 0
    ) {
        return -1;
    }

    char request[
        HTTP_MAX_REQUEST_LEN
    ];

    size_t request_len =
        http_build_get_request(
            request,
            sizeof(request),
            host,
            path
        );

    if (
        request_len == 0
    ) {
        return -1;
    }

    tcp_segment_t request_segment;

    if (
        tcp_connection_build_data(
            &connection,
            &request_segment,
            (const uint8_t *)request,
            request_len,
            TCP_WINDOW_SIZE
        ) != 0
    ) {
        return -1;
    }

    printf(
        "HTTP GET %s\n",
        path
    );

    printf(
        "TCP  SEND         seq=%u bytes=%zu ack=%u\n",
        request_segment.sequence_number,
        request_len,
        request_segment.acknowledgment_number
    );

    if (
        send_tcp_segment(
            dev,
            target_ip,
            next_hop_mac,
            &request_segment
        ) != 0
    ) {
        return -1;
    }

    size_t response_capacity =
        HTTP_RESPONSE_INITIAL_CAPACITY;

    char *response_data =
        malloc(
            response_capacity
        );

    if (
        response_data ==
        NULL
    ) {
        return -1;
    }

    response_data[0] =
        '\0';

    size_t response_len =
        0;

    struct timespec start;

    if (
        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        ) != 0
    ) {
        free(response_data);

        return -1;
    }

    int remote_closed =
        0;

    while (
        !remote_closed
    ) {
        struct timespec now;

        if (
            clock_gettime(
                CLOCK_MONOTONIC,
                &now
            ) != 0
        ) {
            free(response_data);

            return -1;
        }

        if (
            elapsed_ms(
                &start,
                &now
            ) >
            HTTP_TIMEOUT_MS
        ) {
            fprintf(
                stderr,
                "HTTP response timed out.\n"
            );

            break;
        }

        tcp_segment_t incoming;

        int receive_result =
            receive_tcp_segment(
                dev,
                target_ip,
                &incoming,
                TCP_POLL_MS
            );

        if (
            receive_result < 0
        ) {
            free(response_data);

            return -1;
        }

        if (
            receive_result == 0
        ) {
            tcp_segment_t retransmit;

            int retransmit_result =
                tcp_connection_tick(
                    &connection,
                    TCP_POLL_MS,
                    &retransmit
                );

            if (
                retransmit_result < 0
            ) {
                fprintf(
                    stderr,
                    "TCP retransmission limit reached.\n"
                );

                free(response_data);

                return -1;
            }

            if (
                retransmit_result == 1
            ) {
                printf(
                    "TCP  RETRANSMIT   %s seq=%u retry=%u\n",
                    tcp_state_flag_name(
                        retransmit.flags
                    ),
                    retransmit.sequence_number,
                    connection.retransmit_count
                );

                if (
                    send_tcp_segment(
                        dev,
                        target_ip,
                        next_hop_mac,
                        &retransmit
                    ) != 0
                ) {
                    free(response_data);

                    return -1;
                }
            }

            continue;
        }

        if (
            (incoming.flags &
            TCP_FLAG_RST) != 0
        ) {
            (void)
                tcp_connection_on_segment(
                    &connection,
                    &incoming
                );

            fprintf(
                stderr,
                "TCP connection reset.\n"
            );

            free(response_data);

            return -1;
        }

        uint32_t expected_before =
            connection.receive_next;

        size_t queue_before =
            tcp_connection_reassembly_count(
                &connection
            );

        tcp_connection_state_t state_before =
            connection.state;

        int state_result =
            tcp_connection_on_segment(
                &connection,
                &incoming
            );

        if (
            state_result == -2
        ) {
            fprintf(
                stderr,
                "TCP receive/reassembly capacity exhausted.\n"
            );

            free(response_data);

            return -1;
        }

        if (
            state_result < 0
        ) {
            continue;
        }

        size_t queue_after =
            tcp_connection_reassembly_count(
                &connection
            );

        /*
         * Diagnostic only.
         *
         * Reassembly policy is owned entirely by tcp_connection_t.
         */
        if (
            incoming.payload_len > 0
        ) {
            if (
                incoming.sequence_number >
                expected_before
            ) {
                printf(
                    "TCP  BUFFER       seq=%u expected=%u bytes=%zu queue=%zu\n",
                    incoming.sequence_number,
                    expected_before,
                    incoming.payload_len,
                    queue_after
                );
            } else if (
                incoming.sequence_number <
                    expected_before &&
                connection.receive_next ==
                    expected_before
            ) {
                printf(
                    "TCP  DUPLICATE    seq=%u bytes=%zu ack=%u\n",
                    incoming.sequence_number,
                    incoming.payload_len,
                    connection.receive_next
                );
            }

            if (
                queue_after <
                queue_before
            ) {
                printf(
                    "TCP  REASSEMBLE   promoted=%zu ack=%u\n",
                    queue_before -
                    queue_after,
                    connection.receive_next
                );
            }
        }

        /*
         * Drain whatever the TCP engine now considers contiguous.
         *
         * This may include:
         *
         * - the current segment
         * - clipped overlap bytes
         * - one or several previously buffered segments
         */
        if (
            drain_tcp_application_data(
                &connection,
                &response_data,
                &response_len,
                &response_capacity
            ) != 0
        ) {
            fprintf(
                stderr,
                "HTTP response too large.\n"
            );

            free(response_data);

            return -1;
        }

        /*
         * ACK after every payload/FIN-bearing segment.
         *
         * receive_next already represents the highest contiguous
         * sequence edge after reassembly.
         */
        if (
            incoming.payload_len > 0 ||
            (incoming.flags &
            TCP_FLAG_FIN) != 0
        ) {
            if (
                send_connection_ack(
                    dev,
                    target_ip,
                    next_hop_mac,
                    &connection
                ) != 0
            ) {
                free(response_data);

                return -1;
            }
        }

        if (
            state_before !=
                TCP_STATE_CLOSE_WAIT &&
            connection.state ==
                TCP_STATE_CLOSE_WAIT
        ) {
            printf(
                "TCP  FIN RECEIVED  ack=%u state=%s\n",
                connection.receive_next,
                tcp_connection_state_name(
                    connection.state
                )
            );

            remote_closed =
                1;
        } else if (
            (incoming.flags &
            TCP_FLAG_FIN) != 0 &&
            connection.pending_fin
        ) {
            printf(
                "TCP  FIN PENDING   seq=%u expected=%u\n",
                connection.pending_fin_sequence,
                connection.receive_next
            );
        }
    }

    /*
     * One final drain in case reassembly promotion occurred on the
     * segment that also completed connection close.
     */
    if (
        drain_tcp_application_data(
            &connection,
            &response_data,
            &response_len,
            &response_capacity
        ) != 0
    ) {
        free(response_data);

        return -1;
    }

    if (
        response_len == 0
    ) {
        fprintf(
            stderr,
            "No HTTP response data received.\n"
        );

        free(response_data);

        return -1;
    }

    if (
        print_http_response(
            response_data,
            response_len
        ) != 0
    ) {
        free(response_data);

        return -1;
    }

    if (
        connection.state ==
        TCP_STATE_CLOSE_WAIT
    ) {
        tcp_segment_t fin;

        if (
            tcp_connection_build_fin(
                &connection,
                &fin,
                TCP_WINDOW_SIZE
            ) == 0
        ) {
            printf(
                "\nTCP  FIN SEND     seq=%u ack=%u state=%s\n",
                fin.sequence_number,
                fin.acknowledgment_number,
                tcp_connection_state_name(
                    connection.state
                )
            );

            (void)
                send_tcp_segment(
                    dev,
                    target_ip,
                    next_hop_mac,
                    &fin
                );
        }
    }

    free(response_data);

    return 0;
}

int main(
    int argc,
    char **argv
)
{
    if (
        argc != 5
    ) {
        fprintf(
            stderr,
            "Usage: %s <interface> <target-ip> <host> <path>\n",
            argv[0]
        );

        return 1;
    }

    const char *interface_name =
        argv[1];

    const char *target_text =
        argv[2];

    const char *host =
        argv[3];

    const char *path =
        argv[4];

    struct in_addr address;

    if (
        inet_pton(
            AF_INET,
            target_text,
            &address
        ) != 1
    ) {
        fprintf(
            stderr,
            "Invalid IPv4 address.\n"
        );

        return 1;
    }

    uint8_t target_ip[
        IPV4_ADDR_LEN
    ];

    memcpy(
        target_ip,
        &address,
        IPV4_ADDR_LEN
    );

    netdev_t dev;

    if (
        netdev_open(
            &dev,
            interface_name
        ) != 0
    ) {
        return 1;
    }

    printf(
        "\nBLACKTERM // NETSTACK HTTP\n\n"
    );

    printf(
        "interface: %s\n",
        dev.name
    );

    printf(
        "local IPv4: "
    );

    print_ipv4(
        dev.ipv4
    );

    printf("\n");

    printf(
        "target: "
    );

    print_ipv4(
        target_ip
    );

    printf(
        ":%d\n",
        HTTP_DESTINATION_PORT
    );

    printf(
        "host: %s\n",
        host
    );

    printf(
        "path: %s\n",
        path
    );

    uint8_t next_hop_ip[
        IPV4_ADDR_LEN
    ];

    if (
        netdev_ipv4_is_local(
            &dev,
            target_ip
        )
    ) {
        memcpy(
            next_hop_ip,
            target_ip,
            IPV4_ADDR_LEN
        );

        printf(
            "route: direct\n\n"
        );
    } else {
        if (
            !dev.has_gateway
        ) {
            fprintf(
                stderr,
                "No default gateway.\n"
            );

            netdev_close(
                &dev
            );

            return 1;
        }

        memcpy(
            next_hop_ip,
            dev.gateway,
            IPV4_ADDR_LEN
        );

        printf(
            "route: via "
        );

        print_ipv4(
            dev.gateway
        );

        printf(
            "\n\n"
        );
    }

    uint8_t next_hop_mac[
        ETHERNET_ADDR_LEN
    ];

    if (
        resolve_arp(
            &dev,
            next_hop_ip,
            next_hop_mac
        ) != 0
    ) {
        netdev_close(
            &dev
        );

        return 1;
    }

    int result =
        run_http(
            &dev,
            target_ip,
            next_hop_mac,
            host,
            path
        );

    netdev_close(
        &dev
    );

    return
        result == 0
        ? 0
        : 1;
}
