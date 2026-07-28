#define _POSIX_C_SOURCE 200809L

#include "arp.h"
#include "ethernet.h"
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

#define TCP_SOURCE_PORT 40000
#define TCP_WINDOW_SIZE 64240

static void print_ipv4(const uint8_t ip[4])
{
    printf(
        "%u.%u.%u.%u",
        (unsigned int)ip[0],
        (unsigned int)ip[1],
        (unsigned int)ip[2],
        (unsigned int)ip[3]
    );
}

static void print_mac(const uint8_t mac[6])
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
        ((double)(end->tv_sec - start->tv_sec) * 1000.0) +
        ((double)(end->tv_nsec - start->tv_nsec) / 1000000.0);
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
        return 0x12345678U;
    }

    uint64_t mixed =
        ((uint64_t)now.tv_sec << 32) ^
        (uint64_t)now.tv_nsec;

    mixed ^= mixed >> 33;
    mixed *= UINT64_C(0xff51afd7ed558ccd);
    mixed ^= mixed >> 33;

    return (uint32_t)mixed;
}

static int resolve_arp(
    netdev_t *dev,
    const uint8_t next_hop_ip[4],
    uint8_t next_hop_mac[6]
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
            ) > ARP_TIMEOUT_MS
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

        if (received <= 0) {
            continue;
        }

        ethernet_frame_t incoming_eth;

        if (
            ethernet_parse(
                receive_buffer,
                (size_t)received,
                &incoming_eth
            ) != 0
        ) {
            continue;
        }

        if (
            incoming_eth.ethertype !=
            ETHERNET_TYPE_ARP
        ) {
            continue;
        }

        arp_packet_t reply;

        if (
            arp_parse(
                incoming_eth.payload,
                incoming_eth.payload_len,
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

static int send_tcp_frame(
    netdev_t *dev,
    const uint8_t target_ip[4],
    const uint8_t next_hop_mac[6],
    const tcp_segment_t *segment
)
{
    uint8_t tcp_bytes[
        ETHERNET_MAX_PAYLOAD
    ];

    size_t tcp_len =
        tcp_serialize_ipv4(
            segment,
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
            0x5443
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

    uint8_t frame_bytes[
        ETHERNET_MAX_FRAME_LEN
    ];

    size_t frame_len =
        ethernet_serialize(
            &ethernet,
            frame_bytes,
            sizeof(frame_bytes)
        );

    if (frame_len == 0) {
        return -1;
    }

    return
        netdev_send(
            dev,
            frame_bytes,
            frame_len
        ) < 0
            ? -1
            : 0;
}

static int wait_for_syn_ack(
    netdev_t *dev,
    const uint8_t target_ip[4],
    uint16_t target_port,
    uint32_t client_isn,
    tcp_segment_t *reply,
    double *rtt_ms
)
{
    uint8_t receive_buffer[
        RECEIVE_BUFFER_SIZE
    ];

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
            ) > TCP_TIMEOUT_MS
        ) {
            fprintf(
                stderr,
                "TCP SYN timed out.\n"
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

        if (received <= 0) {
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

        tcp_segment_t tcp;

        if (
            tcp_parse(
                ip.payload,
                ip.payload_len,
                &tcp
            ) != 0
        ) {
            continue;
        }

        if (
            tcp.source_port !=
            target_port
        ) {
            continue;
        }

        if (
            tcp.destination_port !=
            TCP_SOURCE_PORT
        ) {
            continue;
        }

        if (
            (tcp.flags & TCP_FLAG_RST) != 0
        ) {
            fprintf(
                stderr,
                "TCP connection reset by remote host.\n"
            );

            return -1;
        }

        if (
            (tcp.flags &
            (TCP_FLAG_SYN | TCP_FLAG_ACK)) !=
            (TCP_FLAG_SYN | TCP_FLAG_ACK)
        ) {
            continue;
        }

        if (
            tcp.acknowledgment_number !=
            client_isn + 1U
        ) {
            continue;
        }

        struct timespec end;

        if (
            clock_gettime(
                CLOCK_MONOTONIC,
                &end
            ) != 0
        ) {
            return -1;
        }

        *reply = tcp;

        if (rtt_ms != NULL) {
            *rtt_ms =
                elapsed_ms(
                    &start,
                    &end
                );
        }

        return 0;
    }
}

static int perform_handshake(
    netdev_t *dev,
    const uint8_t target_ip[4],
    uint16_t target_port,
    const uint8_t next_hop_mac[6]
)
{
    uint32_t client_isn =
        generate_isn();

    tcp_segment_t syn;

    if (
        tcp_build(
            &syn,
            TCP_SOURCE_PORT,
            target_port,
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
        "TCP  SYN      %u -> %u seq=%u\n",
        TCP_SOURCE_PORT,
        target_port,
        client_isn
    );

    if (
        send_tcp_frame(
            dev,
            target_ip,
            next_hop_mac,
            &syn
        ) != 0
    ) {
        fprintf(
            stderr,
            "Failed to send SYN.\n"
        );

        return -1;
    }

    tcp_segment_t syn_ack;
    double syn_rtt = 0.0;

    if (
        wait_for_syn_ack(
            dev,
            target_ip,
            target_port,
            client_isn,
            &syn_ack,
            &syn_rtt
        ) != 0
    ) {
        return -1;
    }

    printf(
        "TCP  SYN-ACK  %u <- %u seq=%u ack=%u time=%.2f ms\n",
        TCP_SOURCE_PORT,
        target_port,
        syn_ack.sequence_number,
        syn_ack.acknowledgment_number,
        syn_rtt
    );

    uint32_t client_seq =
        client_isn + 1U;

    uint32_t server_next_seq =
        syn_ack.sequence_number + 1U;

    tcp_segment_t ack;

    if (
        tcp_build(
            &ack,
            TCP_SOURCE_PORT,
            target_port,
            client_seq,
            server_next_seq,
            TCP_FLAG_ACK,
            TCP_WINDOW_SIZE,
            NULL,
            0
        ) != 0
    ) {
        return -1;
    }

    if (
        send_tcp_frame(
            dev,
            target_ip,
            next_hop_mac,
            &ack
        ) != 0
    ) {
        fprintf(
            stderr,
            "Failed to send ACK.\n"
        );

        return -1;
    }

    printf(
        "TCP  ACK      seq=%u ack=%u\n",
        client_seq,
        server_next_seq
    );

    printf(
        "\nTCP STATE: ESTABLISHED\n"
    );

    /*
     * We are not implementing full graceful shutdown yet.
     * Send a userspace RST so the remote peer does not retain
     * the connection after our handshake demo exits.
     */
    tcp_segment_t rst;

    if (
        tcp_build(
            &rst,
            TCP_SOURCE_PORT,
            target_port,
            client_seq,
            server_next_seq,
            TCP_FLAG_RST |
            TCP_FLAG_ACK,
            0,
            NULL,
            0
        ) == 0
    ) {
        (void)send_tcp_frame(
            dev,
            target_ip,
            next_hop_mac,
            &rst
        );

        printf(
            "TCP  RST      connection closed\n"
        );
    }

    return 0;
}

int main(
    int argc,
    char **argv
)
{
    if (argc != 4) {
        fprintf(
            stderr,
            "Usage: %s <interface> <target-ip> <port>\n",
            argv[0]
        );

        return 1;
    }

    const char *interface_name =
        argv[1];

    const char *target_text =
        argv[2];

    char *port_end = NULL;

    unsigned long port_value =
        strtoul(
            argv[3],
            &port_end,
            10
        );

    if (
        port_end == argv[3] ||
        *port_end != '\0' ||
        port_value == 0 ||
        port_value > 65535
    ) {
        fprintf(
            stderr,
            "Invalid TCP port: %s\n",
            argv[3]
        );

        return 1;
    }

    uint16_t target_port =
        (uint16_t)port_value;

    struct in_addr addr;

    if (
        inet_pton(
            AF_INET,
            target_text,
            &addr
        ) != 1
    ) {
        fprintf(
            stderr,
            "Invalid IPv4 address: %s\n",
            target_text
        );

        return 1;
    }

    uint8_t target_ip[4];

    memcpy(
        target_ip,
        &addr,
        sizeof(target_ip)
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
        "\nBLACKTERM // NETSTACK TCP\n\n"
    );

    printf(
        "interface: %s\n",
        dev.name
    );

    printf("local IPv4: ");
    print_ipv4(dev.ipv4);
    printf("\n");

    printf(
        "source port: %u\n",
        TCP_SOURCE_PORT
    );

    printf("target: ");
    print_ipv4(target_ip);

    printf(
        ":%u\n",
        target_port
    );

    uint8_t next_hop_ip[4];

    if (
        netdev_ipv4_is_local(
            &dev,
            target_ip
        )
    ) {
        memcpy(
            next_hop_ip,
            target_ip,
            sizeof(next_hop_ip)
        );

        printf(
            "route: direct\n\n"
        );
    } else {
        if (!dev.has_gateway) {
            fprintf(
                stderr,
                "No default gateway found.\n"
            );

            netdev_close(&dev);

            return 1;
        }

        memcpy(
            next_hop_ip,
            dev.gateway,
            sizeof(next_hop_ip)
        );

        printf("route: via ");
        print_ipv4(dev.gateway);
        printf("\n\n");
    }

    uint8_t next_hop_mac[6];

    if (
        resolve_arp(
            &dev,
            next_hop_ip,
            next_hop_mac
        ) != 0
    ) {
        netdev_close(&dev);

        return 1;
    }

    int result =
        perform_handshake(
            &dev,
            target_ip,
            target_port,
            next_hop_mac
        );

    netdev_close(&dev);

    return
        result == 0
        ? 0
        : 1;
}
