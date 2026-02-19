/**
 * @file zt_zap.c
 * @brief ZAP framing implementation for ZT connections.
 */

#include "zt/zt_zap.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void zt_zap_encode_header(uint8_t header[ZT_ZAP_HEADER_SIZE], uint32_t length)
{
    header[0] = (uint8_t)(length >> 24);
    header[1] = (uint8_t)(length >> 16);
    header[2] = (uint8_t)(length >> 8);
    header[3] = (uint8_t)(length);
}

uint32_t zt_zap_decode_header(const uint8_t header[ZT_ZAP_HEADER_SIZE])
{
    return ((uint32_t)header[0] << 24) |
           ((uint32_t)header[1] << 16) |
           ((uint32_t)header[2] << 8) |
           ((uint32_t)header[3]);
}

/**
 * Read exactly `len` bytes from fd into buf.
 * Returns 0 on success, -1 on error or EOF.
 */
static int read_exact(int fd, uint8_t *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            if (n == 0) {
                errno = ECONNRESET;
            }
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

/**
 * Write exactly `len` bytes from buf to fd.
 * Returns 0 on success, -1 on error.
 */
static int write_exact(int fd, const uint8_t *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n <= 0) {
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

int zt_zap_send_frame(int fd, const uint8_t *data, size_t len)
{
    if (len > ZT_ZAP_MAX_MESSAGE_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    /* Encode and send length header */
    uint8_t header[ZT_ZAP_HEADER_SIZE];
    zt_zap_encode_header(header, (uint32_t)len);

    if (write_exact(fd, header, ZT_ZAP_HEADER_SIZE) != 0) {
        return -1;
    }

    /* Send payload */
    if (len > 0 && write_exact(fd, data, len) != 0) {
        return -1;
    }

    return 0;
}

int zt_zap_recv_frame(int fd, uint8_t **out_data, size_t *out_len)
{
    if (!out_data || !out_len) {
        errno = EINVAL;
        return -1;
    }

    /* Read length header */
    uint8_t header[ZT_ZAP_HEADER_SIZE];
    if (read_exact(fd, header, ZT_ZAP_HEADER_SIZE) != 0) {
        return -1;
    }

    uint32_t length = zt_zap_decode_header(header);
    if (length > ZT_ZAP_MAX_MESSAGE_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    /* Allocate and read payload */
    uint8_t *data = NULL;
    if (length > 0) {
        data = (uint8_t *)malloc(length);
        if (!data) {
            errno = ENOMEM;
            return -1;
        }

        if (read_exact(fd, data, length) != 0) {
            free(data);
            return -1;
        }
    }

    *out_data = data;
    *out_len = length;
    return 0;
}
