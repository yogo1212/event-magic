#ifndef BASE64_H
#define BASE64_H

#include <stdbool.h>

/**
 * usage
 * =====
 *
 * encode
 * ------
 *
 * char databuf[databuf_len];
 *
 * base64_init();
 * size_t el = base64_encode_len(databuf_len);
 * char *ebuf = malloc(el);
 * base64_encode(databuf, databuf_len, ebuf);
 *
 * decode
 * ------
 *
 * char databuf[databuf_len];
 *
 * base64_init();
 * size_t dl = base64_decode_len(databuf_len);
 * char *dbuf = malloc(dl);
 * base64_decode(databuf, databuf_len, dbuf);
 *
 */

size_t base64_encode_len(size_t input_length);
bool base64_encode(const uint8_t *data, size_t input_length, char *encoded_data);
size_t base64_decode_len(const char *data, size_t input_length);
bool base64_decode(const char *data, size_t input_length, uint8_t *decoded_data);

void base64_init(void);

#endif /* BASE64_H */
