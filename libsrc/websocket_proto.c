#include <string.h>

#include "websocket_proto.h"

void _websocket_session_pack_header(ws_frame_header_info_t *info, struct evbuffer *evb)
{
	uint8_t buf = info->fin ? 0x80 : 0;
	buf |= (info->opcode & 0xF);
	evbuffer_add(evb, &buf, sizeof(buf));

	buf = info->masked ? 0x80 : 0;
	if (info->payload_len > UINT16_MAX) {
		buf |= 127;
		evbuffer_add(evb, &buf, sizeof(buf));
		uint64_t tmp64 = htobe64(info->payload_len);
		evbuffer_add(evb, &tmp64, sizeof(tmp64));
	}
	else if (info->payload_len > 125) {
		buf |= 126;
		evbuffer_add(evb, &buf, sizeof(buf));
		uint16_t tmp16 = htons(info->payload_len);
		evbuffer_add(evb, &tmp16, sizeof(tmp16));
	}
	else {
		buf |= (info->payload_len & 0x7F);
		evbuffer_add(evb, &buf, sizeof(buf));
	}

	if (info->masked) {
		evbuffer_add(evb, info->mask, 4);
	}
}

size_t _websocket_session_try_to_fetch_header(struct evbuffer *evb, ws_frame_header_info_t *info)
{
	uint8_t buf[WS_MAX_HEADER_SIZE];
	ssize_t read_len = evbuffer_copyout(evb, buf, sizeof(buf));
	uint8_t *pos = buf;

	// 1-fin, 3-rsvd, 4-opcode, 1-mask, 7-preliminary length
	info->fin = (buf[0] & 0x80) != 0;
	info->opcode = buf[0] & 0xF;
	info->masked = (buf[1] & 0x80) != 0;
	info->payload_len = buf[1] & 0x7F;
	pos += 2;

	if (info->payload_len == 126) {
		pos += 2;
		if (read_len < (pos - buf))
			goto end;
		info->payload_len = ntohs(*((uint16_t *) (pos - 2)));
	}
	else if (info->payload_len == 127) {
		pos += 8;
		if (read_len < (pos - buf))
			goto end;
		info->payload_len = be64toh(*((uint64_t *) (pos - 8)));
	}

	if (info->masked) {
		pos += 4;
		if (read_len < (pos - buf))
			goto end;
		memcpy(info->mask, pos - 4, 4);
	}

end:
	return pos - buf;
}
