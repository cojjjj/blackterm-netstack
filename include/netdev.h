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
} netdev_t;

/*
 * Open a Linux AF_PACKET socket bound to an interface.
 *
 * Returns:
 *   0 success
 *  -1 failure
 */
int netdev_open(
    netdev_t *dev,
    const char *interface_name
);

/*
 * Close the underlying socket.
 */
void netdev_close(netdev_t *dev);

/*
 * Send a raw Ethernet frame.
 *
 * Returns number of bytes sent, or -1 on failure.
 */
long netdev_send(
    const netdev_t *dev,
    const uint8_t *frame,
    size_t frame_len
);

/*
 * Receive a raw Ethernet frame.
 *
 * timeout_ms:
 *   < 0 = wait forever
 *   = 0 = poll
 *   > 0 = wait up to timeout
 *
 * Returns:
 *   >0 bytes received
 *    0 timeout
 *   -1 error
 */
long netdev_receive(
    const netdev_t *dev,
    uint8_t *buffer,
    size_t buffer_len,
    int timeout_ms
);

/*
 * Determine whether an IPv4 target is on the same subnet.
 */
int netdev_ipv4_is_local(
    const netdev_t *dev,
    const uint8_t target_ip[NETDEV_IPV4_LEN]
);

#endif
