#include "ethernet.h"

#include <stdio.h>
#include <string.h>

static uint16_t read_u16_be(const uint8_t *data)
{
    return (uint16_t)(
        ((uint16_t)data[0] << 8) |
        ((uint16_t)data[1])
    );
}

static void write_u16_be(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)((value >> 8) & 0xFF);
    data[1] = (uint8_t)(value & 0xFF);
}

int ethernet_parse(
    const uint8_t *data,
    size_t data_len,
    ethernet_frame_t *frame
)
{
    if (data == NULL || frame == NULL) {
        return -1;
    }

    if (data_len < ETHERNET_HEADER_LEN) {
        return -2;
    }

    size_t payload_len = data_len - ETHERNET_HEADER_LEN;

    if (payload_len > ETHERNET_MAX_PAYLOAD) {
        return -3;
    }

    memset(frame, 0, sizeof(*frame));

    memcpy(frame->destination, data, ETHERNET_ADDR_LEN);

    memcpy(
        frame->source,
        data + ETHERNET_ADDR_LEN,
        ETHERNET_ADDR_LEN
    );

    frame->ethertype = read_u16_be(data + 12);
    frame->payload_len = payload_len;

    if (payload_len > 0) {
        memcpy(
            frame->payload,
            data + ETHERNET_HEADER_LEN,
            payload_len
        );
    }

    return 0;
}

size_t ethernet_serialize(
    const ethernet_frame_t *frame,
    uint8_t *buffer,
    size_t buffer_len
)
{
    if (frame == NULL || buffer == NULL) {
        return 0;
    }

    if (frame->payload_len > ETHERNET_MAX_PAYLOAD) {
        return 0;
    }

    size_t required_len =
        ETHERNET_HEADER_LEN + frame->payload_len;

    if (buffer_len < required_len) {
        return 0;
    }

    memcpy(
        buffer,
        frame->destination,
        ETHERNET_ADDR_LEN
    );

    memcpy(
        buffer + ETHERNET_ADDR_LEN,
        frame->source,
        ETHERNET_ADDR_LEN
    );

    write_u16_be(buffer + 12, frame->ethertype);

    if (frame->payload_len > 0) {
        memcpy(
            buffer + ETHERNET_HEADER_LEN,
            frame->payload,
            frame->payload_len
        );
    }

    return required_len;
}

int ethernet_mac_to_string(
    const uint8_t mac[ETHERNET_ADDR_LEN],
    char *buffer,
    size_t buffer_len
)
{
    if (mac == NULL || buffer == NULL) {
        return -1;
    }

    if (buffer_len < 18) {
        return -1;
    }

    int written = snprintf(
        buffer,
        buffer_len,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );

    return written == 17 ? 0 : -1;
}

const char *ethernet_ethertype_name(uint16_t ethertype)
{
    switch (ethertype) {
        case ETHERNET_TYPE_IPV4:
            return "IPv4";

        case ETHERNET_TYPE_ARP:
            return "ARP";

        case ETHERNET_TYPE_IPV6:
            return "IPv6";

        default:
            return "Unknown";
    }
}
