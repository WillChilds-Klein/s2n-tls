/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000

#define STRING_LEN 1024
static char str_buffer[STRING_LEN];
static s2n_blocked_status blocked;

#define SEND(...)                                                              \
    do {                                                                       \
        sprintf(str_buffer, __VA_ARGS__);                                      \
        POSIX_GUARD(s2n_send(conn, str_buffer, strlen(str_buffer), &blocked)); \
    } while (0)

#define BUFFER(...)                                                                                       \
    do {                                                                                                  \
        sprintf(str_buffer, __VA_ARGS__);                                                                 \
        POSIX_GUARD(s2n_stuffer_write_bytes(&stuffer, (const uint8_t *) str_buffer, strlen(str_buffer))); \
    } while (0)

static int flush(uint32_t left, uint8_t *buffer, struct s2n_connection *conn, s2n_blocked_status *blocked_status)
{
    uint32_t i = 0;
    while (i < left) {
        int out = s2n_send(conn, &buffer[i], left - i, blocked_status);
        if (out < 0) {
            fprintf(stderr, "Error writing to connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            s2n_print_stacktrace(stdout);
            return S2N_FAILURE;
        }
        i += out;
    }

    return S2N_SUCCESS;
}

#define HEADERS(length)                         \
    do {                                        \
        SEND("HTTP/1.1 200 OK\r\n");            \
        SEND("Content-Length: %u\r\n", length); \
        SEND("\r\n");                           \
    } while (0)

/* In bench mode, we send some binary output */
int bench_handler(struct s2n_connection *conn, uint32_t bench)
{
    uint8_t big_buff[65536] = { 0 };
    uint32_t buff_len = sizeof(big_buff);
    uint32_t requested_bytes = bench;
    // bench=0 here indicates that the client will determine the number of
    // bytes we send back. expected form of this request is a regular HTTP GET
    // with a single parameter specifying an unit32.
    if (requested_bytes == 0) {
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        size_t bytes_read = 0;
        bytes_read = s2n_recv(conn, big_buff, buff_len, &blocked);
        if (bytes_read <= 0) {
            return S2N_FAILURE;
        }
        // URL query params start after the ?= thing, clients shoud only
        // specify a singe parameter that is an unsigned 32-bit integer
        requested_bytes = strtoul(strchr(big_buff, '=')+1, NULL, 10);
        if (requested_bytes == 0) {
            fprintf(stdout, "BAD PARSE %u\n", requested_bytes);
            return S2N_FAILURE;
        }
    }

    HEADERS(requested_bytes);
    fprintf(stdout, "Sending %u bytes...\n", requested_bytes);

    uint32_t bytes_remaining = requested_bytes;

    struct timespec start, finish;
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    while (bytes_remaining) {
        uint32_t buffer_remaining = bytes_remaining < buff_len ? bytes_remaining : buff_len;
        RAND_bytes(&big_buff[0], buffer_remaining);
        // ASCII 32-127 are printable
        for (int i = 0; i < buffer_remaining; i++) {
            big_buff[i] = 32 + (big_buff[i] % 95);
        }
        POSIX_GUARD(flush(buffer_remaining, big_buff, conn, &blocked));
        bytes_remaining -= buffer_remaining;
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &finish);
    const double handshake_time_ms = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);
    printf("SEND TIME: %f,%u,%u\n", handshake_time_ms, start.tv_sec * MS_IN_S + start.tv_nsec / NS_IN_MS, finish.tv_sec * MS_IN_S + finish.tv_nsec / NS_IN_MS);

    fprintf(stdout, "Done. Closing connection.\n\n");

    return S2N_SUCCESS;
}

/*
 * simple https handler that allows https clients to connect
 * but currently does not do any user parsing
 */
int https(struct s2n_connection *conn)
{
    DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_growable_alloc(&stuffer, 1024));

    BUFFER("<html><body><h1>Hello from s2n server</h1><pre>");

    BUFFER("Client hello version: %d\n", s2n_connection_get_client_hello_version(conn));
    BUFFER("Client protocol version: %d\n", s2n_connection_get_client_protocol_version(conn));
    BUFFER("Server protocol version: %d\n", s2n_connection_get_server_protocol_version(conn));
    BUFFER("Actual protocol version: %d\n", s2n_connection_get_actual_protocol_version(conn));

    if (s2n_get_server_name(conn)) {
        BUFFER("Server name: %s\n", s2n_get_server_name(conn));
    }

    if (s2n_get_application_protocol(conn)) {
        BUFFER("Application protocol: %s\n", s2n_get_application_protocol(conn));
    }

    BUFFER("Curve: %s\n", s2n_connection_get_curve(conn));
    BUFFER("KEM: %s\n", s2n_connection_get_kem_name(conn));
    BUFFER("KEM Group: %s\n", s2n_connection_get_kem_group_name(conn));
    BUFFER("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));
    BUFFER("Session resumption: %s\n", s2n_connection_is_session_resumed(conn) ? "true" : "false");

    uint32_t content_length = s2n_stuffer_data_available(&stuffer);

    uint8_t *content = s2n_stuffer_raw_read(&stuffer, content_length);
    POSIX_ENSURE_REF(content);

    HEADERS(content_length);
    POSIX_GUARD(flush(content_length, content, conn, &blocked));

    return S2N_SUCCESS;
}
