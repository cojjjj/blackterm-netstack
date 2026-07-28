#define _POSIX_C_SOURCE 200809L

#include "arp.h"
#include "dns.h"
#include "ethernet.h"
#include "ipv4.h"
#include "netdev.h"
#include "udp.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define RECEIVE_BUFFER_SIZE 2048

#define ARP_TIMEOUT_MS 3000
#define DNS_TIMEOUT_MS 5000

#define DNS_DESTINATION_PORT 53
#define DNS_SOURCE_PORT 53000

#define DNS_TRANSACTION_ID 0x4242

static void print_ipv4(
    const uint8_t ip[4]
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
    const uint8_t mac[6]
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

static int resolve_arp(
    netdev_t *dev,
    const uint8_t next_hop_ip[4],
    uint8_t next_hop_mac[6]
)
{
    arp_packet_t arp;

    if (
        arp_build_request(
            &arp,
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
            &arp,
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

    uint8_t bytes[ETHERNET_MAX_FRAME_LEN];

    size_t frame_len =
        ethernet_serialize(
            &frame,
            bytes,
            sizeof(bytes)
        );

    if (frame_len == 0) {
        return -1;
    }

    if (
        netdev_send(
            dev,
            bytes,
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
                4
            ) != 0
        ) {
            continue;
        }

        memcpy(
            next_hop_mac,
            reply.sender_mac,
            6
        );

        printf("ARP  ");
        print_ipv4(next_hop_ip);

        printf(" is-at ");

        print_mac(next_hop_mac);

        printf("\n");

        return 0;
    }
}

static int send_dns_query(
    netdev_t *dev,
    const uint8_t server_ip[4],
    const uint8_t next_hop_mac[6],
    const char *hostname
)
{
    /*
     * DNS
     */

    uint8_t dns_bytes[
        DNS_MAX_PACKET_LEN
    ];

    size_t dns_len =
        dns_build_a_query(
            dns_bytes,
            sizeof(dns_bytes),
            DNS_TRANSACTION_ID,
            hostname
        );

    if (dns_len == 0) {
        fprintf(
            stderr,
            "Could not construct DNS query.\n"
        );

        return -1;
    }

    /*
     * UDP
     */

    udp_packet_t udp;

    if (
        udp_build(
            &udp,
            DNS_SOURCE_PORT,
            DNS_DESTINATION_PORT,
            dns_bytes,
            dns_len
        ) != 0
    ) {
        return -1;
    }

    uint8_t udp_bytes[
        UDP_MAX_PACKET_LEN
    ];

    size_t udp_len =
        udp_serialize_ipv4(
            &udp,
            dev->ipv4,
            server_ip,
            udp_bytes,
            sizeof(udp_bytes)
        );

    if (udp_len == 0) {
        return -1;
    }

    /*
     * IPv4
     */

    ipv4_packet_t ipv4;

    if (
        ipv4_build(
            &ipv4,
            dev->ipv4,
            server_ip,
            IPV4_PROTOCOL_UDP,
            udp_bytes,
            udp_len,
            64,
            0x444E
        ) != 0
    ) {
        return -1;
    }

    uint8_t ipv4_bytes[
        ETHERNET_MAX_PAYLOAD
    ];

    size_t ipv4_len =
        ipv4_serialize(
            &ipv4,
            ipv4_bytes,
            sizeof(ipv4_bytes)
        );

    if (ipv4_len == 0) {
        return -1;
    }

    /*
     * Ethernet
     */

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
        ipv4_bytes,
        ipv4_len
    );

    ethernet.payload_len =
        ipv4_len;

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

    struct timespec start;

    if (
        clock_gettime(
            CLOCK_MONOTONIC,
            &start
        ) != 0
    ) {
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

    printf(
        "DNS  query A %s -> ",
        hostname
    );

    print_ipv4(server_ip);

    printf(
        ":%u\n",
        DNS_DESTINATION_PORT
    );

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
            ) > DNS_TIMEOUT_MS
        ) {
            fprintf(
                stderr,
                "DNS request timed out.\n"
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
            ETHERNET_TYPE_IPV4
        ) {
            continue;
        }

        ipv4_packet_t incoming_ip;

        if (
            ipv4_parse(
                incoming_eth.payload,
                incoming_eth.payload_len,
                &incoming_ip
            ) != 0
        ) {
            continue;
        }

        if (
            incoming_ip.protocol !=
            IPV4_PROTOCOL_UDP
        ) {
            continue;
        }

        if (
            memcmp(
                incoming_ip.source_ip,
                server_ip,
                4
            ) != 0
        ) {
            continue;
        }

        if (
            memcmp(
                incoming_ip.destination_ip,
                dev->ipv4,
                4
            ) != 0
        ) {
            continue;
        }

        if (
            !udp_checksum_ipv4_valid(
                incoming_ip.source_ip,
                incoming_ip.destination_ip,
                incoming_ip.payload,
                incoming_ip.payload_len
            )
        ) {
            continue;
        }

        udp_packet_t incoming_udp;

        if (
            udp_parse(
                incoming_ip.payload,
                incoming_ip.payload_len,
                &incoming_udp
            ) != 0
        ) {
            continue;
        }

        if (
            incoming_udp.source_port !=
            DNS_DESTINATION_PORT
        ) {
            continue;
        }

        if (
            incoming_udp.destination_port !=
            DNS_SOURCE_PORT
        ) {
            continue;
        }

        dns_response_t response;

        int dns_result =
            dns_parse_response(
                incoming_udp.payload,
                incoming_udp.payload_len,
                DNS_TRANSACTION_ID,
                &response
            );

        if (dns_result != 0) {
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

        printf(
            "DNS  response code=%s time=%.2f ms\n",
            dns_response_code_name(
                response.response_code
            ),
            elapsed_ms(
                &start,
                &end
            )
        );

        if (
            response.response_code != 0
        ) {
            return 1;
        }

        if (
            response.answer_count == 0
        ) {
            printf(
                "No IPv4 A records returned.\n"
            );

            return 0;
        }

        for (
            size_t i = 0;
            i < response.answer_count;
            i++
        ) {
            printf(
                "A    %s    ",
                hostname
            );

            print_ipv4(
                response.answers[i].address
            );

            printf(
                "    ttl=%u\n",
                (unsigned int)
                response.answers[i].ttl
            );
        }

        return 0;
    }
}

int main(
    int argc,
    char **argv
)
{
    if (argc != 4) {
        fprintf(
            stderr,
            "Usage: %s <interface> <dns-server> <hostname>\n",
            argv[0]
        );

        return 1;
    }

    const char *interface_name =
        argv[1];

    const char *dns_server_text =
        argv[2];

    const char *hostname =
        argv[3];

    struct in_addr server_addr;

    if (
        inet_pton(
            AF_INET,
            dns_server_text,
            &server_addr
        ) != 1
    ) {
        fprintf(
            stderr,
            "Invalid DNS server IPv4 address.\n"
        );

        return 1;
    }

    uint8_t server_ip[4];

    memcpy(
        server_ip,
        &server_addr,
        4
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
        "\nBLACKTERM // NETSTACK DNS\n\n"
    );

    printf(
        "interface: %s\n",
        dev.name
    );

    printf("local IPv4: ");
    print_ipv4(dev.ipv4);
    printf("\n");

    printf("DNS server: ");
    print_ipv4(server_ip);
    printf("\n");

    printf(
        "hostname: %s\n",
        hostname
    );

    uint8_t next_hop_ip[4];

    if (
        netdev_ipv4_is_local(
            &dev,
            server_ip
        )
    ) {
        memcpy(
            next_hop_ip,
            server_ip,
            4
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
            4
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
        send_dns_query(
            &dev,
            server_ip,
            next_hop_mac,
            hostname
        );

    netdev_close(&dev);

    return result == 0 ? 0 : 1;
}
