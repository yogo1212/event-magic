#ifndef _WEBSOCKET_PROTO_H
#define _WEBSOCKET_PROTO_H

#include <stdbool.h>

#include <event2/buffer.h>

enum WS_OPCODE {
  WS_FRAME_CONT = 0,
  WS_FRAME_TEXT = 1,
  WS_FRAME_BIN = 2,
  WS_FRAME_CLOSE = 8,
  WS_FRAME_PING = 9,
  WS_FRAME_PONG = 10
};

typedef struct {
  bool fin;
  uint8_t opcode;
  bool masked;
  uint64_t payload_len;
  uint8_t mask[4];
} ws_frame_header_info_t;

#define WS_MIN_HEADER_SIZE 2
#define WS_MAX_HEADER_SIZE 80
/*
 * tries to fill the struct without draining the buffer
 * returns the minimum size of the header
 * - knowing only about what is there already
 */
size_t _websocket_session_try_to_fetch_header(struct evbuffer *evb, ws_frame_header_info_t *info);
void _websocket_session_pack_header(ws_frame_header_info_t *info, struct evbuffer *evb);

#endif
