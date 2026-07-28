#include "http.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_build_get(void)
{
    char request[
        HTTP_MAX_REQUEST_LEN
    ];

    size_t length =
        http_build_get_request(
            request,
            sizeof(request),
            "example.com",
            "/"
        );

    assert(length > 0);

    assert(
        strstr(
            request,
            "GET / HTTP/1.1\r\n"
        ) != NULL
    );

    assert(
        strstr(
            request,
            "Host: example.com\r\n"
        ) != NULL
    );

    assert(
        strstr(
            request,
            "Connection: close\r\n"
        ) != NULL
    );

    assert(
        length >= 4
    );

    assert(
        strcmp(
            request +
            length - 4,
            "\r\n\r\n"
        ) == 0
    );
}

static void test_parse_response(void)
{
    const char response_text[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";

    http_response_t response;

    assert(
        http_parse_response(
            response_text,
            sizeof(response_text) - 1,
            &response
        ) == 0
    );

    assert(
        response.status_code ==
        200
    );

    assert(
        strcmp(
            response.status_text,
            "OK"
        ) == 0
    );

    assert(
        response.body_len ==
        5
    );

    assert(
        memcmp(
            response.body,
            "hello",
            5
        ) == 0
    );
}

static void test_parse_redirect(void)
{
    const char response_text[] =
        "HTTP/1.1 301 Moved Permanently\r\n"
        "Location: https://example.com/\r\n"
        "\r\n";

    http_response_t response;

    assert(
        http_parse_response(
            response_text,
            sizeof(response_text) - 1,
            &response
        ) == 0
    );

    assert(
        response.status_code ==
        301
    );

    assert(
        strcmp(
            response.status_text,
            "Moved Permanently"
        ) == 0
    );
}

static void test_invalid_response(void)
{
    const char malformed[] =
        "NOT HTTP\r\n\r\n";

    http_response_t response;

    assert(
        http_parse_response(
            malformed,
            sizeof(malformed) - 1,
            &response
        ) == -2
    );
}

static void test_incomplete_headers(void)
{
    const char incomplete[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n";

    http_response_t response;

    assert(
        http_parse_response(
            incomplete,
            sizeof(incomplete) - 1,
            &response
        ) == -3
    );
}

int main(void)
{
    test_build_get();
    test_parse_response();
    test_parse_redirect();

    test_invalid_response();
    test_incomplete_headers();

    printf(
        "[PASS] HTTP GET construction\n"
        "[PASS] HTTP Host header\n"
        "[PASS] HTTP response parsing\n"
        "[PASS] HTTP status parsing\n"
        "[PASS] HTTP body detection\n"
        "[PASS] Invalid HTTP rejection\n"
        "\n"
        "BLACKTERM // NETSTACK HTTP tests passed.\n"
    );

    return 0;
}
