/**
 * @file zt_zap.h
 * @brief ZAP framing helpers for ZT connections.
 *
 * Provides length-prefixed message framing suitable for Cap'n Proto RPC
 * over ZT connections. Messages use a 4-byte big-endian length prefix
 * followed by the message payload.
 *
 * Usage:
 *   zt_socket_t fd = zt_socket(ZTS_AF_INET, ZTS_SOCK_STREAM, 0);
 *   zt_connect(fd, ...);
 *
 *   // Send a ZAP frame
 *   uint8_t msg[] = {0x01, 0x02, 0x03};
 *   zt_zap_send_frame(fd, msg, sizeof(msg));
 *
 *   // Receive a ZAP frame
 *   uint8_t *data = NULL;
 *   size_t len = 0;
 *   zt_zap_recv_frame(fd, &data, &len);
 *   // ... use data ...
 *   free(data);
 */

#ifndef ZT_ZAP_H
#define ZT_ZAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum ZAP message size: 16 MB */
#define ZT_ZAP_MAX_MESSAGE_SIZE (16 * 1024 * 1024)

/** ZAP frame header size: 4 bytes (big-endian uint32) */
#define ZT_ZAP_HEADER_SIZE 4

/**
 * Send a length-prefixed ZAP frame over a ZT connection.
 *
 * @param fd     ZT socket file descriptor
 * @param data   Message payload
 * @param len    Payload length in bytes
 * @return 0 on success, -1 on error (check errno)
 */
int zt_zap_send_frame(int fd, const uint8_t *data, size_t len);

/**
 * Receive a length-prefixed ZAP frame from a ZT connection.
 *
 * The caller is responsible for freeing *out_data with free().
 *
 * @param fd        ZT socket file descriptor
 * @param out_data  Pointer to receive allocated message buffer
 * @param out_len   Pointer to receive message length
 * @return 0 on success, -1 on error
 */
int zt_zap_recv_frame(int fd, uint8_t **out_data, size_t *out_len);

/**
 * Encode a ZAP frame header (4-byte big-endian length).
 *
 * @param header  Output buffer (must be at least ZT_ZAP_HEADER_SIZE bytes)
 * @param length  Message length to encode
 */
void zt_zap_encode_header(uint8_t header[ZT_ZAP_HEADER_SIZE], uint32_t length);

/**
 * Decode a ZAP frame header.
 *
 * @param header  Input buffer (4 bytes)
 * @return Decoded message length
 */
uint32_t zt_zap_decode_header(const uint8_t header[ZT_ZAP_HEADER_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ZT_ZAP_H */
