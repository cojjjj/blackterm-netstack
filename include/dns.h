#ifndef BLACKTERM_DNS_H
#define BLACKTERM_DNS_H

#include <stddef.h>
#include <stdint.h>

#define DNS_HEADER_LEN 12
#define DNS_MAX_PACKET_LEN 512

#define DNS_TYPE_A 1
#define DNS_CLASS_IN 1

#define DNS_MAX_ANSWERS 16

typedef struct {
    uint8_t address[4];
    uint32_t ttl;
} dns_a_record_t;

typedef struct {
    uint16_t transaction_id;

    uint8_t response_code;
    uint8_t authoritative;
    uint8_t truncated;
    uint8_t recursion_available;

    dns_a_record_t answers[DNS_MAX_ANSWERS];
    size_t answer_count;
} dns_response_t;

/*
 * Construct a standard recursive DNS A query.
 *
 * Returns packet length on success.
 * Returns 0 on failure.
 */
size_t dns_build_a_query(
    uint8_t *buffer,
    size_t buffer_len,
    uint16_t transaction_id,
    const char *hostname
);

/*
 * Parse a DNS response and extract IPv4 A records.
 *
 * Returns:
 *   0  success
 *  -1  invalid arguments
 *  -2  packet too short
 *  -3  transaction ID mismatch
 *  -4  packet is not a DNS response
 *  -5  malformed packet
 */
int dns_parse_response(
    const uint8_t *data,
    size_t data_len,
    uint16_t expected_transaction_id,
    dns_response_t *response
);

const char *dns_response_code_name(
    uint8_t response_code
);

#endif
