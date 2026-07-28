#define _DEFAULT_SOURCE

#include "netdev.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int copy_interface_name(
    struct ifreq *ifr,
    const char *name
)
{
    if (ifr == NULL || name == NULL) {
        return -1;
    }

    size_t name_len = strlen(name);

    if (
        name_len == 0 ||
        name_len >= IF_NAMESIZE
    ) {
        return -1;
    }

    memset(ifr, 0, sizeof(*ifr));

    memcpy(
        ifr->ifr_name,
        name,
        name_len + 1
    );

    return 0;
}

static int get_interface_mac(
    int fd,
    const char *name,
    uint8_t mac[NETDEV_MAC_LEN]
)
{
    if (
        fd < 0 ||
        name == NULL ||
        mac == NULL
    ) {
        return -1;
    }

    struct ifreq ifr;

    if (
        copy_interface_name(
            &ifr,
            name
        ) != 0
    ) {
        return -1;
    }

    if (
        ioctl(
            fd,
            SIOCGIFHWADDR,
            &ifr
        ) < 0
    ) {
        return -1;
    }

    memcpy(
        mac,
        ifr.ifr_hwaddr.sa_data,
        NETDEV_MAC_LEN
    );

    return 0;
}

static int get_interface_ipv4(
    int fd,
    const char *name,
    uint8_t ipv4[NETDEV_IPV4_LEN]
)
{
    if (
        fd < 0 ||
        name == NULL ||
        ipv4 == NULL
    ) {
        return -1;
    }

    struct ifreq ifr;

    if (
        copy_interface_name(
            &ifr,
            name
        ) != 0
    ) {
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;

    if (
        ioctl(
            fd,
            SIOCGIFADDR,
            &ifr
        ) < 0
    ) {
        return -1;
    }

    const struct sockaddr_in *addr =
        (const struct sockaddr_in *)&ifr.ifr_addr;

    memcpy(
        ipv4,
        &addr->sin_addr,
        NETDEV_IPV4_LEN
    );

    return 0;
}

static int get_interface_netmask(
    int fd,
    const char *name,
    uint8_t netmask[NETDEV_IPV4_LEN]
)
{
    if (
        fd < 0 ||
        name == NULL ||
        netmask == NULL
    ) {
        return -1;
    }

    struct ifreq ifr;

    if (
        copy_interface_name(
            &ifr,
            name
        ) != 0
    ) {
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;

    if (
        ioctl(
            fd,
            SIOCGIFNETMASK,
            &ifr
        ) < 0
    ) {
        return -1;
    }

    const struct sockaddr_in *addr =
        (const struct sockaddr_in *)&ifr.ifr_netmask;

    memcpy(
        netmask,
        &addr->sin_addr,
        NETDEV_IPV4_LEN
    );

    return 0;
}

int netdev_open(
    netdev_t *dev,
    const char *interface_name
)
{
    if (
        dev == NULL ||
        interface_name == NULL
    ) {
        return -1;
    }

    size_t name_len =
        strlen(interface_name);

    if (
        name_len == 0 ||
        name_len >= sizeof(dev->name) ||
        name_len >= IF_NAMESIZE
    ) {
        return -1;
    }

    memset(
        dev,
        0,
        sizeof(*dev)
    );

    dev->fd = -1;

    int fd = socket(
        AF_PACKET,
        SOCK_RAW,
        htons(ETH_P_ALL)
    );

    if (fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    unsigned int interface_index =
        if_nametoindex(interface_name);

    if (interface_index == 0) {
        fprintf(
            stderr,
            "Unknown interface: %s\n",
            interface_name
        );

        close(fd);
        return -1;
    }

    struct sockaddr_ll bind_address;

    memset(
        &bind_address,
        0,
        sizeof(bind_address)
    );

    bind_address.sll_family =
        AF_PACKET;

    bind_address.sll_protocol =
        htons(ETH_P_ALL);

    bind_address.sll_ifindex =
        (int)interface_index;

    if (
        bind(
            fd,
            (struct sockaddr *)&bind_address,
            sizeof(bind_address)
        ) < 0
    ) {
        perror("bind(AF_PACKET)");

        close(fd);
        return -1;
    }

    dev->fd =
        fd;

    dev->ifindex =
        (int)interface_index;

    memcpy(
        dev->name,
        interface_name,
        name_len + 1
    );

    if (
        get_interface_mac(
            fd,
            interface_name,
            dev->mac
        ) != 0
    ) {
        perror("SIOCGIFHWADDR");

        netdev_close(dev);
        return -1;
    }

    if (
        get_interface_ipv4(
            fd,
            interface_name,
            dev->ipv4
        ) != 0
    ) {
        perror("SIOCGIFADDR");

        netdev_close(dev);
        return -1;
    }

    if (
        get_interface_netmask(
            fd,
            interface_name,
            dev->netmask
        ) != 0
    ) {
        perror("SIOCGIFNETMASK");

        netdev_close(dev);
        return -1;
    }

    return 0;
}

void netdev_close(netdev_t *dev)
{
    if (dev == NULL) {
        return;
    }

    if (dev->fd >= 0) {
        close(dev->fd);
    }

    dev->fd = -1;
    dev->ifindex = 0;
}

long netdev_send(
    const netdev_t *dev,
    const uint8_t *frame,
    size_t frame_len
)
{
    if (
        dev == NULL ||
        dev->fd < 0 ||
        frame == NULL ||
        frame_len == 0
    ) {
        return -1;
    }

    ssize_t sent = send(
        dev->fd,
        frame,
        frame_len,
        0
    );

    if (sent < 0) {
        perror("send");
        return -1;
    }

    return (long)sent;
}

long netdev_receive(
    const netdev_t *dev,
    uint8_t *buffer,
    size_t buffer_len,
    int timeout_ms
)
{
    if (
        dev == NULL ||
        dev->fd < 0 ||
        buffer == NULL ||
        buffer_len == 0
    ) {
        return -1;
    }

    struct pollfd pfd;

    memset(
        &pfd,
        0,
        sizeof(pfd)
    );

    pfd.fd =
        dev->fd;

    pfd.events =
        POLLIN;

    int poll_result;

    do {
        poll_result = poll(
            &pfd,
            1,
            timeout_ms
        );
    } while (
        poll_result < 0 &&
        errno == EINTR
    );

    if (poll_result == 0) {
        return 0;
    }

    if (poll_result < 0) {
        perror("poll");
        return -1;
    }

    if (
        (pfd.revents & POLLIN) == 0
    ) {
        return 0;
    }

    ssize_t received = recv(
        dev->fd,
        buffer,
        buffer_len,
        0
    );

    if (received < 0) {
        perror("recv");
        return -1;
    }

    return (long)received;
}

int netdev_ipv4_is_local(
    const netdev_t *dev,
    const uint8_t target_ip[NETDEV_IPV4_LEN]
)
{
    if (
        dev == NULL ||
        target_ip == NULL
    ) {
        return 0;
    }

    for (
        size_t i = 0;
        i < NETDEV_IPV4_LEN;
        i++
    ) {
        uint8_t local_network =
            (uint8_t)(
                dev->ipv4[i] &
                dev->netmask[i]
            );

        uint8_t target_network =
            (uint8_t)(
                target_ip[i] &
                dev->netmask[i]
            );

        if (
            local_network !=
            target_network
        ) {
            return 0;
        }
    }

    return 1;
}
