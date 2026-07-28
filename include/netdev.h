#ifndef BLACKTERM_NETDEV_H
#define BLACKTERM_NETDEV_H

#include <stddef.h>
#include <stdint.h>

#define NETDEV_MAC_LEN 6
#define NETDEV_IPV4_LEN 4

typedef struct {
    int fd;
    int ifindex;

    char name[64];

    uint8_t mac[NETDEV_MAC_LEN];
    uint8_t ipv4[NETDEV_IPV4_LEN];
    uint8_t netmask[NETDEV_IPV4_LEN];

    uint8_t gateway[NETDEV_IPV4_LEN];
    int has_gateway;
} netdev_t;

/*
 * Open a Linux AF_PACKET socket bound to an interface.
 *
 * Also discovers:
 *   MAC address
 *   IPv4 address
 *   subnet mask
 *   default IPv4 gateway
 *
 * Returns:
 *   0 success
 *  -1 failure
 */
int netdev_open(
    netdev_t *dev,
    const char *interface_name
);

void netdev_close(netdev_t *dev);

long netdev_send(
    const netdev_t *dev,
    const uint8_t *frame,
    size_t frame_len
);

long netdev_receive(
    const netdev_t *dev,
    uint8_t *buffer,
    size_t buffer_len,
    int timeout_ms
);

/*
 * Returns 1 when target_ip is on the interface's local subnet.
 */
int netdev_ipv4_is_local(
    const netdev_t *dev,
    const uint8_t target_ip[NETDEV_IPV4_LEN]
);

#endif
