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
#include <openssl/rand.h>

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

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
    HEADERS(bench);
    fprintf(stdout, "Sending %u bytes...\n", bench);

    uint8_t big_buff[65536] = { 0 };
    uint32_t len = sizeof(big_buff);
    uint32_t bytes_remaining = bench;

    while (bytes_remaining) {
        uint32_t buffer_remaining = bytes_remaining < len ? bytes_remaining : len;
        POSIX_GUARD(flush(buffer_remaining, big_buff, conn, &blocked));
        bytes_remaining -= buffer_remaining;
    }

    fprintf(stdout, "Done. Closing connection.\n\n");

    return 0;
}

/*
 * simple https handler that allows https clients to connect
 * but currently does not do any user parsing
 */
int https(struct s2n_connection *conn, uint32_t bench)
{
    if (bench) {
        return bench_handler(conn, bench);
    }

    DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
    const int buff_size = 1024;
    POSIX_GUARD(s2n_stuffer_growable_alloc(&stuffer, buff_size));

    int remaining = 150000;
    uint8_t buffer[buff_size];
    while (remaining > 0) {
        // need to leave room for null terminator
        int to_write = (sizeof(buffer)-1) < remaining ? sizeof(buffer)-1 : remaining;
        RAND_bytes(&buffer, to_write);
        for (int i = 0; i < to_write; i++) {
            buffer[i] = 97 + (buffer[i] % 26);
        }
        buffer[to_write] = 0;
        BUFFER("%s", buffer);
        remaining -= to_write;
    }

    uint32_t content_length = s2n_stuffer_data_available(&stuffer);

    uint8_t *content = s2n_stuffer_raw_read(&stuffer, content_length);
    POSIX_ENSURE_REF(content);

    HEADERS(content_length);
    POSIX_GUARD(flush(content_length, content, conn, &blocked));

    return S2N_SUCCESS;
}
