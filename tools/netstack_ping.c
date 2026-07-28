#define _POSIX_C_SOURCE 200809L

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "netdev.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define RECEIVE_BUFFER_SIZE 2048

#define ARP_TIMEOUT_MS 3000
#define ICMP_TIMEOUT_MS 5000

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

static double elapsed_ms(
    const struct timespec *start,
    const struct timespec *end
)
{
    double seconds =
        (double)(
            end->tv_sec -
            start->tv_sec
        );

    double nanoseconds =
        (double)(
            end->tv_nsec -
            start->tv_nsec
        );

    return
        (seconds * 1000.0) +
        (nanoseconds / 1000000.0);
}

static int resolve_arp(
    netdev_t *dev,
    const uint8_t next_hop_ip[IPV4_ADDR_LEN],
    uint8_t next_hop_mac[ETHERNET_ADDR_LEN]
)
{
    arp_packet_t arp_request;

    if (
        arp_build_request(
            &arp_request,
            dev->mac,
            dev->ipv4,
            next_hop_ip
        ) != 0
    ) {
        fprintf(
            stderr,
            "Failed to build ARP request.\n"
        );

        return -1;
    }

    uint8_t arp_bytes[ARP_PACKET_LEN];

    size_t arp_len = arp_serialize(
        &arp_request,
        arp_bytes,
        sizeof(arp_bytes)
    );

    if (arp_len == 0) {
        fprintf(
            stderr,
            "Failed to serialize ARP request.\n"
        );

        return -1;
    }

    ethernet_frame_t ethernet = {0};

    memset(
        ethernet.destination,
        0xFF,
        ETHERNET_ADDR_LEN
    );

    memcpy(
        ethernet.source,
        dev->mac,
        ETHERNET_ADDR_LEN
    );

    ethernet.ethertype =
        ETHERNET_TYPE_ARP;

    memcpy(
        ethernet.payload,
        arp_bytes,
        arp_len
    );

    ethernet.payload_len =
        arp_len;

    uint8_t frame_bytes[
        ETHERNET_MAX_FRAME_LEN
    ];

    size_t frame_len = ethernet_serialize(
        &ethernet,
        frame_bytes,
        sizeof(frame_bytes)
    );

    if (frame_len == 0) {
        fprintf(
            stderr,
            "Failed to serialize ARP frame.\n"
        );

        return -1;
    }

    if (
        netdev_send(
            dev,
            frame_bytes,
            frame_len
        ) < 0
    ) {
        fprintf(
            stderr,
            "Failed to transmit ARP request.\n"
        );

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

        long received = netdev_receive(
            dev,
            receive_buffer,
            sizeof(receive_buffer),
            250
        );

        if (received <= 0) {
            continue;
        }

        ethernet_frame_t incoming;

        if (
            ethernet_parse(
                receive_buffer,
                (size_t)received,
                &incoming
            ) != 0
        ) {
            continue;
        }

        if (
            incoming.ethertype !=
            ETHERNET_TYPE_ARP
        ) {
            continue;
        }

        arp_packet_t reply;

        if (
            arp_parse(
                incoming.payload,
                incoming.payload_len,
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

static int send_ping(
    netdev_t *dev,
    const uint8_t target_ip[IPV4_ADDR_LEN],
    const uint8_t next_hop_mac[ETHERNET_ADDR_LEN]
)
{
    static const uint8_t payload[] =
        "BLACKTERM // NETSTACK";

    const uint16_t identifier =
        0x4242;

    const uint16_t sequence =
        1;

    /*
     * ICMP
     */

    icmp_packet_t icmp;

    if (
        icmp_build_echo_request(
            &icmp,
            identifier,
            sequence,
            payload,
            sizeof(payload) - 1
        ) != 0
    ) {
        return -1;
    }

    uint8_t icmp_bytes[
        ICMP_MAX_PACKET_LEN
    ];

    size_t icmp_len = icmp_serialize(
        &icmp,
        icmp_bytes,
        sizeof(icmp_bytes)
    );

    if (icmp_len == 0) {
        return -1;
    }

    /*
     * IPv4 destination remains the real target,
     * even when Ethernet goes to a gateway.
     */

    ipv4_packet_t ipv4;

    if (
        ipv4_build(
            &ipv4,
            dev->ipv4,
            target_ip,
            IPV4_PROTOCOL_ICMP,
            icmp_bytes,
            icmp_len,
            64,
            0x1337
        ) != 0
    ) {
        return -1;
    }

    uint8_t ipv4_bytes[
        ETHERNET_MAX_PAYLOAD
    ];

    size_t ipv4_len = ipv4_serialize(
        &ipv4,
        ipv4_bytes,
        sizeof(ipv4_bytes)
    );

    if (ipv4_len == 0) {
        return -1;
    }

    /*
     * Ethernet destination is the next hop.
     *
     * Local host:
     *   next_hop_mac = target MAC
     *
     * Remote host:
     *   next_hop_mac = gateway MAC
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

    size_t frame_len = ethernet_serialize(
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
        "ICMP echo request id=0x%04X seq=%u\n",
        identifier,
        (unsigned int)sequence
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
            ) > ICMP_TIMEOUT_MS
        ) {
            fprintf(
                stderr,
                "ICMP request timed out.\n"
            );

            return -1;
        }

        long received = netdev_receive(
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
            IPV4_PROTOCOL_ICMP
        ) {
            continue;
        }

        if (
            memcmp(
                incoming_ip.source_ip,
                target_ip,
                IPV4_ADDR_LEN
            ) != 0
        ) {
            continue;
        }

        if (
            memcmp(
                incoming_ip.destination_ip,
                dev->ipv4,
                IPV4_ADDR_LEN
            ) != 0
        ) {
            continue;
        }

        icmp_packet_t incoming_icmp;

        if (
            icmp_parse(
                incoming_ip.payload,
                incoming_ip.payload_len,
                &incoming_icmp
            ) != 0
        ) {
            continue;
        }

        if (
            incoming_icmp.type !=
            ICMP_TYPE_ECHO_REPLY
        ) {
            continue;
        }

        if (
            incoming_icmp.identifier != identifier ||
            incoming_icmp.sequence != sequence
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

        printf("ICMP echo reply from ");

        print_ipv4(target_ip);

        printf(
            " ttl=%u seq=%u time=%.2f ms\n",
            (unsigned int)incoming_ip.ttl,
            (unsigned int)incoming_icmp.sequence,
            elapsed_ms(
                &start,
                &end
            )
        );

        return 0;
    }
}

int main(
    int argc,
    char **argv
)
{
    if (argc != 3) {
        fprintf(
            stderr,
            "Usage: %s <interface> <target-ip>\n",
            argv[0]
        );

        return 1;
    }

    const char *interface_name =
        argv[1];

    const char *target_text =
        argv[2];

    struct in_addr target_addr;

    if (
        inet_pton(
            AF_INET,
            target_text,
            &target_addr
        ) != 1
    ) {
        fprintf(
            stderr,
            "Invalid IPv4 address: %s\n",
            target_text
        );

        return 1;
    }

    uint8_t target_ip[
        IPV4_ADDR_LEN
    ];

    memcpy(
        target_ip,
        &target_addr,
        sizeof(target_ip)
    );

    netdev_t dev;

    if (
        netdev_open(
            &dev,
            interface_name
        ) != 0
    ) {
        fprintf(
            stderr,
            "Could not open interface %s.\n",
            interface_name
        );

        return 1;
    }

    printf(
        "\nBLACKTERM // NETSTACK\n\n"
    );

    printf(
        "interface: %s\n",
        dev.name
    );

    printf("local MAC: ");
    print_mac(dev.mac);
    printf("\n");

    printf("local IPv4: ");
    print_ipv4(dev.ipv4);
    printf("\n");

    printf("netmask: ");
    print_ipv4(dev.netmask);
    printf("\n");

    if (dev.has_gateway) {
        printf("gateway: ");
        print_ipv4(dev.gateway);
        printf("\n");
    }

    printf("target: ");
    print_ipv4(target_ip);
    printf("\n");

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
        if (!dev.has_gateway) {
            fprintf(
                stderr,
                "\nNo default gateway found.\n"
            );

            netdev_close(&dev);

            return 1;
        }

        memcpy(
            next_hop_ip,
            dev.gateway,
            IPV4_ADDR_LEN
        );

        printf("route: via ");

        print_ipv4(dev.gateway);

        printf("\n\n");
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
        netdev_close(&dev);

        return 1;
    }

    int result = send_ping(
        &dev,
        target_ip,
        next_hop_mac
    );

    netdev_close(&dev);

    return result == 0 ? 0 : 1;
}
