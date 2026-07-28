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

static void test_chunked_detection(void)
{
    const char response_text[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\n"
        "hello\r\n"
        "0\r\n"
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
        http_response_is_chunked(
            response_text,
            response.header_len
        ) == 1
    );
}

static void test_chunked_detection_case_insensitive(void)
{
    const char response_text[] =
        "HTTP/1.1 200 OK\r\n"
        "transfer-encoding: Chunked\r\n"
        "\r\n"
        "0\r\n"
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
        http_response_is_chunked(
            response_text,
            response.header_len
        ) == 1
    );
}

static void test_decode_chunked_body(void)
{
    const char chunked[] =
        "4\r\n"
        "Wiki\r\n"
        "5\r\n"
        "pedia\r\n"
        "0\r\n"
        "\r\n";

    char output[64];

    size_t length =
        http_decode_chunked_body(
            chunked,
            sizeof(chunked) - 1,
            output,
            sizeof(output)
        );

    assert(
        length ==
        strlen("Wikipedia")
    );

    assert(
        strcmp(
            output,
            "Wikipedia"
        ) == 0
    );
}

static void test_decode_realistic_chunk(void)
{
    const char chunked[] =
        "5\r\n"
        "hello\r\n"
        "1\r\n"
        " \r\n"
        "5\r\n"
        "world\r\n"
        "0\r\n"
        "\r\n";

    char output[64];

    size_t length =
        http_decode_chunked_body(
            chunked,
            sizeof(chunked) - 1,
            output,
            sizeof(output)
        );

    assert(length == 11);

    assert(
        strcmp(
            output,
            "hello world"
        ) == 0
    );
}

static void test_chunk_extension(void)
{
    const char chunked[] =
        "5;foo=bar\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n";

    char output[64];

    size_t length =
        http_decode_chunked_body(
            chunked,
            sizeof(chunked) - 1,
            output,
            sizeof(output)
        );

    assert(length == 5);

    assert(
        strcmp(
            output,
            "hello"
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

static void test_invalid_chunked_body(void)
{
    const char bad[] =
        "ZZ\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n";

    char output[64];

    assert(
        http_decode_chunked_body(
            bad,
            sizeof(bad) - 1,
            output,
            sizeof(output)
        ) == 0
    );
}

int main(void)
{
    test_build_get();
    test_parse_response();

    test_chunked_detection();
    test_chunked_detection_case_insensitive();

    test_decode_chunked_body();
    test_decode_realistic_chunk();
    test_chunk_extension();

    test_parse_redirect();

    test_invalid_response();
    test_incomplete_headers();
    test_invalid_chunked_body();

    printf(
        "[PASS] HTTP GET construction\n"
        "[PASS] HTTP Host header\n"
        "[PASS] HTTP response parsing\n"
        "[PASS] HTTP status parsing\n"
        "[PASS] HTTP body detection\n"
        "[PASS] Chunked Transfer-Encoding detection\n"
        "[PASS] Chunked body decoding\n"
        "[PASS] Chunk extension handling\n"
        "[PASS] Invalid HTTP rejection\n"
        "\n"
        "BLACKTERM // NETSTACK HTTP tests passed.\n"
    );

    return 0;
}
