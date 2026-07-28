#define _POSIX_C_SOURCE 200809L

#include "arp.h"
#include "ethernet.h"
#include "http.h"
#include "ipv4.h"
#include "netdev.h"
#include "tcp.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RECEIVE_BUFFER_SIZE 2048

#define ARP_TIMEOUT_MS 3000
#define TCP_TIMEOUT_MS 5000
#define HTTP_TIMEOUT_MS 10000

#define HTTP_SOURCE_PORT 40001
#define HTTP_DESTINATION_PORT 80

#define TCP_WINDOW_SIZE 64240

#define HTTP_RESPONSE_INITIAL_CAPACITY 8192
#define HTTP_RESPONSE_MAX_SIZE (1024U * 1024U)

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

    uint8_t arp_bytes[ARP_PACKET_LEN];

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
                250
            );

        if (received < 0) {
            return -1;
        }

        if (received == 0) {
            continue;
        }

        ethernet_frame_t eth;

        if (
            ethernet_parse(
                receive_buffer,
                (size_t)received,
                &eth
            ) != 0
        ) {
            continue;
        }

        if (
            eth.ethertype !=
            ETHERNET_TYPE_ARP
        ) {
            continue;
        }

        arp_packet_t reply;

        if (
            arp_parse(
                eth.payload,
                eth.payload_len,
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

    ethernet_frame_t eth = {0};

    memcpy(
        eth.destination,
        next_hop_mac,
        ETHERNET_ADDR_LEN
    );

    memcpy(
        eth.source,
        dev->mac,
        ETHERNET_ADDR_LEN
    );

    eth.ethertype =
        ETHERNET_TYPE_IPV4;

    memcpy(
        eth.payload,
        ip_bytes,
        ip_len
    );

    eth.payload_len =
        ip_len;

    uint8_t frame[
        ETHERNET_MAX_FRAME_LEN
    ];

    size_t frame_len =
        ethernet_serialize(
            &eth,
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
                250
            );

        if (received < 0) {
            return -1;
        }

        if (received == 0) {
            continue;
        }

        ethernet_frame_t eth;

        if (
            ethernet_parse(
                receive_buffer,
                (size_t)received,
                &eth
            ) != 0
        ) {
            continue;
        }

        if (
            eth.ethertype !=
            ETHERNET_TYPE_IPV4
        ) {
            continue;
        }

        ipv4_packet_t ip;

        if (
            ipv4_parse(
                eth.payload,
                eth.payload_len,
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

static int send_ack(
    netdev_t *dev,
    const uint8_t target_ip[IPV4_ADDR_LEN],
    const uint8_t next_hop_mac[ETHERNET_ADDR_LEN],
    uint32_t seq,
    uint32_t ack
)
{
    tcp_segment_t segment;

    if (
        tcp_build(
            &segment,
            HTTP_SOURCE_PORT,
            HTTP_DESTINATION_PORT,
            seq,
            ack,
            TCP_FLAG_ACK,
            TCP_WINDOW_SIZE,
            NULL,
            0
        ) != 0
    ) {
        return -1;
    }

    return send_tcp_segment(
        dev,
        target_ip,
        next_hop_mac,
        &segment
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
        1
    ) {
        return -1;
    }

    size_t required =
        *length +
        data_len +
        1;

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
                HTTP_RESPONSE_MAX_SIZE / 2
            ) {
                new_capacity =
                    HTTP_RESPONSE_MAX_SIZE;
            } else {
                new_capacity *= 2;
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

static int print_http_response(
    const char *response_data,
    size_t response_len
)
{
    if (
        response_data == NULL ||
        response_len == 0
    ) {
        return -1;
    }

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
            "Received data but could not parse HTTP response.\n"
        );

        return -1;
    }

    int chunked =
        http_response_is_chunked(
            response_data,
            response.header_len
        );

    if (chunked < 0) {
        fprintf(
            stderr,
            "Could not inspect HTTP transfer encoding.\n"
        );

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

    /*
     * Print response headers exactly as received.
     */
    printf("\n--- HEADERS ---\n");

    fwrite(
        response_data,
        1,
        response.header_len,
        stdout
    );

    if (chunked) {
        /*
         * The decoded representation can never be larger
         * than the raw chunked representation, plus the
         * trailing NUL used for convenience.
         */
        size_t decoded_capacity =
            response.body_len + 1;

        char *decoded_body =
            malloc(
                decoded_capacity
            );

        if (
            decoded_body ==
            NULL
        ) {
            return -1;
        }

        size_t decoded_len =
            http_decode_chunked_body(
                response.body,
                response.body_len,
                decoded_body,
                decoded_capacity
            );

        /*
         * A zero-length decoded body is ambiguous with the
         * current decoder API. For our live HTTP GET use case,
         * a nonempty raw body with zero decoded bytes indicates
         * either an empty chunked response or a decode failure.
         *
         * Keep the output safe and informative either way.
         */
        if (
            decoded_len == 0 &&
            response.body_len > 5
        ) {
            fprintf(
                stderr,
                "\nChunked body decoding failed.\n"
            );

            free(
                decoded_body
            );

            return -1;
        }

        printf(
            "\n--- BODY (chunked decoded) ---\n"
        );

        if (
            decoded_len > 0
        ) {
            fwrite(
                decoded_body,
                1,
                decoded_len,
                stdout
            );
        }

        printf(
            "\n\nraw body: %zu bytes"
            "\ndecoded body: %zu bytes\n",
            response.body_len,
            decoded_len
        );

        free(
            decoded_body
        );
    } else {
        printf(
            "\n--- BODY ---\n"
        );

        if (
            response.body_len >
            0
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

static int run_http(
    netdev_t *dev,
    const uint8_t target_ip[IPV4_ADDR_LEN],
    const uint8_t next_hop_mac[ETHERNET_ADDR_LEN],
    const char *host,
    const char *path
)
{
    uint32_t client_isn =
        generate_isn();

    /*
     * SYN
     */

    tcp_segment_t syn;

    if (
        tcp_build(
            &syn,
            HTTP_SOURCE_PORT,
            HTTP_DESTINATION_PORT,
            client_isn,
            0,
            TCP_FLAG_SYN,
            TCP_WINDOW_SIZE,
            NULL,
            0
        ) != 0
    ) {
        return -1;
    }

    printf(
        "TCP  SYN seq=%u\n",
        client_isn
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

    /*
     * SYN-ACK
     */

    tcp_segment_t syn_ack;

    int receive_result =
        receive_tcp_segment(
            dev,
            target_ip,
            &syn_ack,
            TCP_TIMEOUT_MS
        );

    if (
        receive_result != 1
    ) {
        fprintf(
            stderr,
            "No SYN-ACK received.\n"
        );

        return -1;
    }

    if (
        (syn_ack.flags &
        (
            TCP_FLAG_SYN |
            TCP_FLAG_ACK
        )) !=
        (
            TCP_FLAG_SYN |
            TCP_FLAG_ACK
        )
    ) {
        fprintf(
            stderr,
            "Expected SYN-ACK.\n"
        );

        return -1;
    }

    if (
        syn_ack
            .acknowledgment_number !=
        client_isn + 1U
    ) {
        fprintf(
            stderr,
            "Invalid SYN-ACK acknowledgment.\n"
        );

        return -1;
    }

    uint32_t client_seq =
        client_isn + 1U;

    uint32_t server_seq =
        syn_ack.sequence_number +
        1U;

    printf(
        "TCP  SYN-ACK seq=%u ack=%u\n",
        syn_ack.sequence_number,
        syn_ack.acknowledgment_number
    );

    /*
     * Complete three-way handshake.
     */

    if (
        send_ack(
            dev,
            target_ip,
            next_hop_mac,
            client_seq,
            server_seq
        ) != 0
    ) {
        return -1;
    }

    printf(
        "TCP  ESTABLISHED\n"
    );

    /*
     * Build HTTP GET request.
     */

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
        tcp_build(
            &request_segment,
            HTTP_SOURCE_PORT,
            HTTP_DESTINATION_PORT,
            client_seq,
            server_seq,
            TCP_FLAG_PSH |
            TCP_FLAG_ACK,
            TCP_WINDOW_SIZE,
            (const uint8_t *)request,
            request_len
        ) != 0
    ) {
        return -1;
    }

    printf(
        "HTTP GET %s\n",
        path
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

    /*
     * TCP sequence advances by number of payload bytes sent.
     */

    client_seq +=
        (uint32_t)
        request_len;

    /*
     * Response accumulation buffer.
     */

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

    int received_fin =
        0;

    struct timespec start;

    if (
        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        ) != 0
    ) {
        free(
            response_data
        );

        return -1;
    }

    while (
        !received_fin
    ) {
        struct timespec now;

        if (
            clock_gettime(
                CLOCK_MONOTONIC,
                &now
            ) != 0
        ) {
            free(
                response_data
            );

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

        int result =
            receive_tcp_segment(
                dev,
                target_ip,
                &incoming,
                1000
            );

        if (
            result < 0
        ) {
            free(
                response_data
            );

            return -1;
        }

        if (
            result == 0
        ) {
            continue;
        }

        if (
            (incoming.flags &
            TCP_FLAG_RST) != 0
        ) {
            fprintf(
                stderr,
                "Connection reset.\n"
            );

            free(
                response_data
            );

            return -1;
        }

        /*
         * Reject impossible acknowledgements.
         */

        if (
            (incoming.flags &
            TCP_FLAG_ACK) != 0 &&
            incoming
                .acknowledgment_number >
            client_seq
        ) {
            continue;
        }

        /*
         * TCP payload handling.
         */

        if (
            incoming.payload_len >
            0
        ) {
            uint32_t segment_start =
                incoming
                    .sequence_number;

            uint32_t segment_end =
                segment_start +
                (uint32_t)
                incoming
                    .payload_len;

            if (
                segment_start ==
                server_seq
            ) {
                /*
                 * Next contiguous data.
                 */

                if (
                    append_response(
                        &response_data,
                        &response_len,
                        &response_capacity,
                        incoming.payload,
                        incoming.payload_len
                    ) != 0
                ) {
                    fprintf(
                        stderr,
                        "HTTP response too large.\n"
                    );

                    free(
                        response_data
                    );

                    return -1;
                }

                server_seq =
                    segment_end;

                printf(
                    "TCP  DATA seq=%u bytes=%zu total=%zu ack=%u\n",
                    segment_start,
                    incoming.payload_len,
                    response_len,
                    server_seq
                );
            } else if (
                segment_end <=
                server_seq
            ) {
                /*
                 * Fully duplicate/retransmitted segment.
                 */

                printf(
                    "TCP  DUPLICATE seq=%u bytes=%zu ack=%u\n",
                    segment_start,
                    incoming.payload_len,
                    server_seq
                );
            } else {
                /*
                 * Future segment with a gap.
                 *
                 * Do not consume it yet.
                 */

                printf(
                    "TCP  OUT-OF-ORDER seq=%u expected=%u bytes=%zu\n",
                    segment_start,
                    server_seq,
                    incoming.payload_len
                );
            }

            /*
             * ACK highest contiguous server sequence.
             */

            if (
                send_ack(
                    dev,
                    target_ip,
                    next_hop_mac,
                    client_seq,
                    server_seq
                ) != 0
            ) {
                free(
                    response_data
                );

                return -1;
            }
        }

        /*
         * FIN handling.
         */

        if (
            (incoming.flags &
            TCP_FLAG_FIN) != 0
        ) {
            uint32_t fin_sequence =
                incoming
                    .sequence_number +
                (uint32_t)
                incoming
                    .payload_len;

            if (
                fin_sequence ==
                server_seq
            ) {
                /*
                 * FIN consumes one sequence number.
                 */

                server_seq++;

                if (
                    send_ack(
                        dev,
                        target_ip,
                        next_hop_mac,
                        client_seq,
                        server_seq
                    ) != 0
                ) {
                    free(
                        response_data
                    );

                    return -1;
                }

                printf(
                    "TCP  FIN received ack=%u\n",
                    server_seq
                );

                received_fin =
                    1;
            } else {
                /*
                 * FIN came before missing data.
                 *
                 * ACK our current contiguous edge and keep waiting.
                 */

                printf(
                    "TCP  FIN out-of-order seq=%u expected=%u\n",
                    fin_sequence,
                    server_seq
                );

                if (
                    send_ack(
                        dev,
                        target_ip,
                        next_hop_mac,
                        client_seq,
                        server_seq
                    ) != 0
                ) {
                    free(
                        response_data
                    );

                    return -1;
                }
            }
        }
    }

    if (
        response_len == 0
    ) {
        fprintf(
            stderr,
            "No HTTP response data received.\n"
        );

        free(
            response_data
        );

        return -1;
    }

    /*
     * Parse + display HTTP response.
     */

    int print_result =
        print_http_response(
            response_data,
            response_len
        );

    if (
        print_result != 0
    ) {
        free(
            response_data
        );

        return -1;
    }

    /*
     * Send our FIN.
     */

    tcp_segment_t fin;

    if (
        tcp_build(
            &fin,
            HTTP_SOURCE_PORT,
            HTTP_DESTINATION_PORT,
            client_seq,
            server_seq,
            TCP_FLAG_FIN |
            TCP_FLAG_ACK,
            TCP_WINDOW_SIZE,
            NULL,
            0
        ) == 0
    ) {
        if (
            send_tcp_segment(
                dev,
                target_ip,
                next_hop_mac,
                &fin
            ) == 0
        ) {
            printf(
                "\nTCP  FIN sent seq=%u ack=%u\n",
                client_seq,
                server_seq
            );
        }
    }

    free(
        response_data
    );

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
