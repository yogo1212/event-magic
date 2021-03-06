#include <endian.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <event-magic/base64.h>
#include <event-magic/ssl.h>

#include "websocket_proto.h"

#include <event-magic/websocket.h>

typedef enum {
	WS_STATE_INVALID = 0,
	WS_STATE_DISCONNECTED,
	WS_STATE_CONNECTING,
	WS_STATE_HANDSHAKE,
	WS_STATE_CONNECTED,
	WS_STATE_DISCONNECTING
} websocket_session_state_t;

struct outgoing_frame {
	STAILQ_ENTRY(outgoing_frame) frames;
	struct evbuffer *buf;
};

STAILQ_HEAD(outgoing_head, outgoing_frame);

struct websocket_session {
	struct event_base *base;
	char *host;
	char *path;
	char *protocols;
	char *origin;
	char *magic;

	build_connection_t create_connection;
	void *create_connection_arg;
	struct bufferevent *bev;

	websocket_session_dbgcb_t user_dbgcb;
	websocket_session_evtcb_t user_evtcb;
	websocket_session_errcb_t user_errcb;
	websocket_session_messagecb_t user_messagecb;

	struct evbuffer *current_content;
	websocket_session_content_type current_content_type;

	bool outgoing_active;
	struct outgoing_head outgoing_head;

	websocket_session_state_t state;
	void *ctx;
};

static void call_debug_cb(websocket_session_t *ws, const char *fmt, ...)
{
	if (!ws->user_dbgcb)
		return;

	va_list va;
	va_start(va, fmt);

	struct evbuffer *evb = evbuffer_new();
	evbuffer_add_vprintf(evb, fmt, va);

	va_end(va);

	size_t evb_len = evbuffer_get_length(evb);
	char *str = malloc(evb_len + 1);
	evbuffer_remove(evb, str, evb_len);
	str[evb_len] = '\0';

	evbuffer_free(evb);

	ws->user_dbgcb(ws, str);

	free(str);
}

static void call_error_cb(websocket_session_t *ws, websocket_session_error_t err, const char *fmt, ...)
{
	if (!ws->user_errcb)
		return;

	va_list va;
	va_start(va, fmt);

	if (err == WEBSOCKET_SESSION_ERROR_MEMORY) {
		// arr, let's hope, this doesn't use the heap
		char stackstr[1024];
		vsnprintf(stackstr, sizeof(stackstr), fmt, va);
		ws->user_errcb(ws, err, stackstr);
		goto leave;
	}

	struct evbuffer *evb = evbuffer_new();
	evbuffer_add_vprintf(evb, fmt, va);

	size_t evb_len = evbuffer_get_length(evb);
	char *str = malloc(evb_len + 1);
	evbuffer_remove(evb, str, evb_len);
	str[evb_len] = '\0';

	evbuffer_free(evb);

	ws->user_errcb(ws, err, str);

	free(str);

leave:
	va_end(va);
}

static void call_event_cb(websocket_session_t *ws, websocket_session_event_t evt, const char *msg)
{
	if (!ws->user_evtcb)
		return;

	ws->user_evtcb(ws, evt, msg);
}

static void outgoing_frame_free(struct outgoing_frame *f)
{
	evbuffer_free(f->buf);
	free(f);
}

static void websocket_session_writecb(struct bufferevent *bev, void *ctx)
{
	(void) bev;

	websocket_session_t *ws = ctx;

	if (STAILQ_EMPTY(&ws->outgoing_head)) {
		ws->outgoing_active = false;
		bufferevent_disable(ws->bev, EV_WRITE);

		call_debug_cb(ws, "no more messages in queue");
		return;
	}

	call_debug_cb(ws, "fetching next message from queue");

	struct outgoing_frame *f = STAILQ_FIRST(&ws->outgoing_head);
  STAILQ_REMOVE_HEAD(&ws->outgoing_head, frames);
	bufferevent_setwatermark(ws->bev, EV_WRITE, evbuffer_get_length(f->buf), 0);
	bufferevent_write_buffer(ws->bev, f->buf);
	outgoing_frame_free(f);
}

/* takes ownership of evb! */
static void _websocket_session_send_frame(websocket_session_t *ws, struct evbuffer *evb, bool urgent)
{
	if (ws->outgoing_active) {
		struct outgoing_frame *frame = malloc(sizeof(struct outgoing_frame));
		frame->buf = evb;
		if (urgent)
			STAILQ_INSERT_HEAD(&ws->outgoing_head, frame, frames);
		else
			STAILQ_INSERT_TAIL(&ws->outgoing_head, frame, frames);
		call_debug_cb(ws, "putting frame in list for later");
	}
	else {
		ws->outgoing_active = true;
		bufferevent_setwatermark(ws->bev, EV_WRITE, evbuffer_get_length(evb), 0);
		bufferevent_write_buffer(ws->bev, evb);
		evbuffer_free(evb);
		bufferevent_enable(ws->bev, EV_WRITE);
		call_debug_cb(ws, "sending frame directly");
	}
}

// TODO might give this length- and mask-parameters instead of info
static void _mask_buffer(struct evbuffer *in, const ws_frame_header_info_t *info, struct evbuffer *out)
{
	size_t remaining = info->payload_len;
	// hoping size_t is the biggest the ALU can handle natively
	uint32_t maskbuf = *((uint32_t *) info->mask);
	uint32_t databuf;

	while (remaining >= sizeof(maskbuf)) {
		remaining -= sizeof(maskbuf);
		evbuffer_remove(in, &databuf, sizeof(databuf));
		databuf ^= maskbuf;
		evbuffer_add(out, &databuf, sizeof(databuf));
	}

	if (remaining > 0) {
		evbuffer_remove(in, &databuf, remaining);
		databuf ^= maskbuf;
		evbuffer_add(out, &databuf, remaining);
	}
}

/* will generate mask and apply it to the payload. payload will be drained by payload_len */
static void websocket_session_build_and_send_frame(websocket_session_t *ws, ws_frame_header_info_t *info, struct evbuffer *payload)
{
	// TODO payload_len > SIZE_MAX
	struct evbuffer *res = evbuffer_new();
	if (info->masked)
		evutil_secure_rng_get_bytes(info->mask, 4);

	_websocket_session_pack_header(info, res);

	if (info->masked) {
		_mask_buffer(payload, info, res);
	}
	else {
		evbuffer_remove_buffer(payload, res, info->payload_len);
	}

	_websocket_session_send_frame(ws, res, (info->opcode & 0x8) != 0);;
}

void websocket_session_send_message(websocket_session_t *ws, websocket_session_content_type type, struct evbuffer *evb, size_t fragment_size)
{
	ws_frame_header_info_t info;
	if (type == WEBSOCKET_SESSION_FRAME_TYPE_TEXT)
  info.opcode = WS_FRAME_TEXT;
	else if (type == WEBSOCKET_SESSION_FRAME_TYPE_BINARY)
  info.opcode = WS_FRAME_BIN;
	else {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_PROTOCOL, "invalid type %d (user input)", type);
		return;
	}
  info.masked = true;
	evutil_secure_rng_get_bytes(info.mask, 4);

	// TODO stop if len > SIZET_MAX
	// sure. just check if evbuffer_get_size is >SIZET_MAX. the result is size_t. oops.

	do {
		info.fin = (fragment_size == 0) || (fragment_size >= evbuffer_get_length(evb));
		// if info.fin is true then frag_size is zero or bigger than len -> len
		// if it's false frag_size is <>0 and <len -> frag_size
		info.payload_len = info.fin ? evbuffer_get_length(evb) : fragment_size;

		websocket_session_build_and_send_frame(ws, &info, evb);

		info.opcode = WS_FRAME_CONT;
	} while (!info.fin);
}

/*
 * reason can be either of:
 * the reason given by the server (if any) when the state is DISCONNECTING
 * the reason that should be sent to the server when the state is CONNECTED
 */
static void _websocket_session_disconnect(websocket_session_t *ws, const char *reason)
{
	if (ws->state == WS_STATE_DISCONNECTED) {
		return;
	}

	if (ws->state == WS_STATE_CONNECTED) {
		// TODO SEND close

		ws->state = WS_STATE_DISCONNECTING;
		return;
	}

	if (ws->state == WS_STATE_DISCONNECTING) {
		call_event_cb(ws, WEBSOCKET_SESSION_EVENT_DISCONNECTED, reason);

		struct outgoing_frame *f;
		while (!STAILQ_EMPTY(&ws->outgoing_head)) {
			f = STAILQ_FIRST(&ws->outgoing_head);
			STAILQ_REMOVE_HEAD(&ws->outgoing_head, frames);
			outgoing_frame_free(f);
		}

		if (ws->current_content) {
			evbuffer_free(ws->current_content);
			ws->current_content = NULL;
		}
	}

	ws->state = WS_STATE_DISCONNECTED;

	bufferevent_free(ws->bev);
	ws->bev = NULL;
}

static void websocket_session_evtcb(struct bufferevent *bev, short what, void *ctx)
{
	(void) bev;

	websocket_session_t *ws = ctx;
	call_debug_cb(ws, "evtcb with %d\n", what);
	if (what & BEV_EVENT_EOF) {
		if (ws->state != WS_STATE_DISCONNECTING)
			call_error_cb(ws, WEBSOCKET_SESSION_ERROR_NETWORK, "transport closed");
		if (ws->state == WS_STATE_CONNECTED)
			ws->state = WS_STATE_DISCONNECTING;
		_websocket_session_disconnect(ws, NULL);
	}
	if (what & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		if (ws->state == WS_STATE_CONNECTED)
			ws->state = WS_STATE_DISCONNECTING;
		// am i not lazy? they could both appear at once..
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_NETWORK, "transport: %s", (what & BEV_EVENT_ERROR ? "error" : "timeout"));
		_websocket_session_disconnect(ws, NULL);
	}
	if (what & BEV_EVENT_CONNECTED) {
		ws->state = WS_STATE_HANDSHAKE;
	}
}

#define payload_length_error_message "payload-length is more than SIZE_MAX"
#define frame_size_error_message "invalid control frame size"
static void websocket_session_readcb(struct bufferevent *bev, void *ctx)
{
	websocket_session_t *ws = ctx;

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	size_t buf_len = evbuffer_get_length(inbuf);

	ws_frame_header_info_t info;
	size_t header_size = _websocket_session_try_to_fetch_header(inbuf, &info);
	if (header_size > buf_len) {
		bufferevent_setwatermark(bev, EV_READ, header_size, 0);
		return;
	}

	size_t total_size = header_size + info.payload_len;
	if (total_size > buf_len) {
		bufferevent_setwatermark(bev, EV_READ, total_size, 0);
		return;
	}

	//call_debug_cb(ws, "header_size = %zu, payload_len = %zu", header_size, info.payload_len);

	evbuffer_drain(inbuf, header_size);

	if (info.masked) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_PROTOCOL, "received a masked frame from the server.. closing connection");
		_websocket_session_disconnect(ws, "masked frame");
		return;
	}

	if (info.payload_len > SIZE_MAX) {
		// just kill me already..
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_MESSAGE_SIZE, payload_length_error_message);
		struct evbuffer *payload = evbuffer_new();

		{
			// TODO ohh, this is so not nice...
			evbuffer_add_printf(payload, payload_length_error_message);
			ws_frame_header_info_t outinfo = { true, WS_FRAME_CLOSE, true, evbuffer_get_length(payload), {0,0,0,0} };
			websocket_session_build_and_send_frame(ws, &outinfo, payload);
			evbuffer_free(payload);

			bufferevent_flush(ws->bev, EV_WRITE, BEV_NORMAL);
		}

		ws->state = WS_STATE_DISCONNECTING;
		_websocket_session_disconnect(ws, payload_length_error_message);
		return;
	}

	bool has_message = false;
	bool is_first_content = true;
	char control_frame_msg[128];
	switch (info.opcode) {
		case WS_FRAME_CONT:
				is_first_content = false;
		case WS_FRAME_TEXT:
		case WS_FRAME_BIN:
			has_message = true;
			if (info.opcode == WS_FRAME_TEXT)
				ws->current_content_type = WEBSOCKET_SESSION_FRAME_TYPE_TEXT;
			else if (info.opcode == WS_FRAME_BIN)
				ws->current_content_type = WEBSOCKET_SESSION_FRAME_TYPE_BINARY;
			break;
		case WS_FRAME_CLOSE:
		case WS_FRAME_PING:
		case WS_FRAME_PONG:
			// at least they gave this control frames a proper limit
			if (info.payload_len > 125) {
				// TODO ouch here	- can't we still send the close?
				call_error_cb(ws, WEBSOCKET_SESSION_ERROR_MESSAGE_SIZE, frame_size_error_message);
				ws->state = WS_STATE_DISCONNECTING;
				_websocket_session_disconnect(ws, frame_size_error_message);
			}
			evbuffer_remove(inbuf, control_frame_msg, info.payload_len);
			control_frame_msg[info.payload_len] = '\0';
			break;
		default:
			// TODO erroar?
			evbuffer_drain(inbuf, info.payload_len);
			call_debug_cb(ws, "unknown opcode: %d", info.opcode);
	}

	switch (info.opcode) {
		case WS_FRAME_CLOSE:
			ws->state = WS_STATE_DISCONNECTING;
			_websocket_session_disconnect(ws, control_frame_msg);
			break;
		case WS_FRAME_PING:
			call_event_cb(ws, WEBSOCKET_SESSION_EVENT_PING, control_frame_msg);
			struct evbuffer *outbuf = evbuffer_new();
			evbuffer_add(outbuf, control_frame_msg, info.payload_len);
			ws_frame_header_info_t outinfo = { true, WS_FRAME_PONG, true, info.payload_len, {0,0,0,0} };
			websocket_session_build_and_send_frame(ws, &outinfo, outbuf);
			evbuffer_free(outbuf);
			break;
		case WS_FRAME_PONG:
			call_event_cb(ws, WEBSOCKET_SESSION_EVENT_PONG, control_frame_msg);
			break;
	}

	if (has_message) {
		if (is_first_content) {
			if (ws->current_content) {
				call_debug_cb(ws, "dropping unfinished frame");
				evbuffer_free(ws->current_content);
			}
			ws->current_content = evbuffer_new();
		}

		// why did they design it in a way that frames can be that long...
		// if all frames can  be2^64 bytes long and message can consist of an infinite amount of frames..
		// effectively, there is no upper boundary anyway..

		// do the new bytes fit in the buffer?
		size_t diff = SIZE_MAX - evbuffer_get_length(ws->current_content);
		if (info.payload_len > diff) {
			evbuffer_remove_buffer(inbuf, ws->current_content, diff);
			uint64_t remaining = info.payload_len - diff;
			call_error_cb(ws, WEBSOCKET_SESSION_ERROR_MESSAGE_SIZE, "dropping %" PRIu64 " bytes", remaining);
			// the watermarks couldn't have been set to more than SIZE_MAX anyway - else there would have to be a loop draining the input-buffer
			evbuffer_drain(inbuf, remaining);
		}
		else
			evbuffer_remove_buffer(inbuf, ws->current_content, info.payload_len);

		if (info.fin) {
			if (ws->user_messagecb) {
				ws->user_messagecb(ws, ws->current_content_type, ws->current_content);
			}
			evbuffer_free(ws->current_content);
			ws->current_content = NULL;
		}
	}

	bufferevent_setwatermark(bev, EV_READ, WS_MIN_HEADER_SIZE, 0);
	bufferevent_trigger(bev, EV_READ, BEV_OPT_DEFER_CALLBACKS);
}

#define RFC4122_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static bool websocket_session_validate_accept(websocket_session_t *ws, const char *accept)
{
	// TODO
	(void) ws;
	(void) accept;
	return true;
}

#define evbuffer_search_str(evb, str, start) evbuffer_search(evb, str, strlen(str), start)
#define WS_HANDSHAKE_BLANK_LINE_BYTE_COUNT_MAX 2048

static void websocket_session_init_readcb(struct bufferevent *bev, void *ctx)
{
	websocket_session_t *ws = ctx;

	if (ws->state != WS_STATE_HANDSHAKE) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "init_readcb called from this state: %d\n", ws->state);
		_websocket_session_disconnect(ws, NULL);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	size_t reply_len = evbuffer_get_length(inbuf);

	if (reply_len >= WS_HANDSHAKE_BLANK_LINE_BYTE_COUNT_MAX) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "handshake-reply is too long");
		goto fail;
	}

	struct evbuffer_ptr evb_ptr = evbuffer_search_str(inbuf, "\r\n\r\n", NULL);

	if (evb_ptr.pos == -1) {
		call_debug_cb(ws, "wait for more header");
		bufferevent_setwatermark(bev, EV_READ, reply_len + 1, 0);
		bufferevent_trigger(bev, EV_READ, BEV_OPT_DEFER_CALLBACKS);
		return;
	}
	call_debug_cb(ws, "got handshake header header");

	// So now there should be a complete HTTP-Reply
	char *line;
	size_t line_len;

	char *status_code;

	line = evbuffer_readln(inbuf, &line_len, EVBUFFER_EOL_CRLF_STRICT);

	// TODO this will not happen:
	if (!line) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "no line in handshake");
		goto fail;
	}

	call_debug_cb(ws, "first line of reply: ->%s<-", line);

	char *saveptr = NULL;
	strtok_r(line, " ", &saveptr);
	status_code = strtok_r(NULL, " ", &saveptr);

	if (status_code && (strcmp(status_code, "101") != 0)) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "status code not 101 (%s)\n", status_code);
		goto fail;
	}
	free(line);

	char *accepted_protocol = NULL;
	char *key_accept = NULL;
	bool has_upgrade_ws = false, has_connection_upgrade = false;

	char *header_name, *header_opt;
	for (line = evbuffer_readln(inbuf, &line_len, EVBUFFER_EOL_CRLF_STRICT);
			strcmp(line, "") != 0;
			free(line), line = evbuffer_readln(inbuf, &line_len, EVBUFFER_EOL_CRLF_STRICT)) {

		if (!line) {
			call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "header-line NULL!");
			goto fail_vars;
		}

		header_name = strtok_r(line, ":", &saveptr);
		header_opt = strtok_r(NULL, ":", &saveptr);

		if (header_opt[0] == ' ') {
			header_opt++;
		}

		if (!(header_name && header_opt)) {
			call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "couldn't parse header-line (%s)\n", line);
			goto fail_vars;
		}

		call_debug_cb(ws, "received field %s in header: ->%s<-\n", header_name, header_opt);

		if (strcasecmp("Upgrade", header_name) == 0) {
			has_upgrade_ws = strcasecmp("websocket", header_opt) == 0;
		}
		else if (strcasecmp("Connection" , header_name) == 0) {
			has_connection_upgrade = strcasecmp("Upgrade", header_opt) == 0;
		}
		else if (strcasecmp("Sec-WebSocket-Protocol" , header_name) == 0) {
			accepted_protocol = strdup(header_opt);
		}
		else if (strcasecmp("Sec-WebSocket-Accept" , header_name) == 0) {
			key_accept = strdup(header_opt);
		}
		else {
			call_debug_cb(ws, "unknown field %s", header_name);
		}
	}

	free(line);

	if (!key_accept) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "accept-token missing");
		goto fail_vars;
	}

	if (!websocket_session_validate_accept(ws, key_accept)) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "couldn't validate the accept-token");
		goto fail_vars;
	}
	free(key_accept);

	if (!has_upgrade_ws) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "upgrade-header missing");
		goto fail_vars;
	}

	if (!has_connection_upgrade) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_HANDSHAKE, "connection-header missing");
		goto fail_vars;
	}

	ws->state = WS_STATE_CONNECTED;
	call_event_cb(ws, WEBSOCKET_SESSION_EVENT_CONNECTED, accepted_protocol);

	bufferevent_setcb(ws->bev, websocket_session_readcb, websocket_session_writecb, websocket_session_evtcb, ws);
	bufferevent_setwatermark(bev, EV_READ, WS_MIN_HEADER_SIZE, 0);
	bufferevent_trigger(bev, EV_READ, BEV_OPT_DEFER_CALLBACKS);

	return;

fail_vars:
	free(key_accept);
	free(accepted_protocol);

fail:
	_websocket_session_disconnect(ws, NULL);
}

void websocket_session_disconnect(websocket_session_t *ws)
{
	// TODO add parameter to this
	_websocket_session_disconnect(ws, "");
}

static void websocket_session_setup_rng(websocket_session_t *ws)
{
	time_t seed1 = time(NULL);
	void *seed2 = &seed1;
	if (evutil_secure_rng_init() == -1)
		call_debug_cb(ws, "rng_init failed");
	evutil_secure_rng_add_bytes((char *) &seed1, sizeof(seed1));
	evutil_secure_rng_add_bytes((char *) &seed2, sizeof(seed2));
	seed2 = ws;
	evutil_secure_rng_add_bytes((char *) &seed2, sizeof(seed2));
}

static char *websocket_session_build_magic(websocket_session_t *ws)
{
	(void) ws;

	uint8_t bytes[16];
	evutil_secure_rng_get_bytes(bytes, 16);
	char *res = malloc(base64_encode_len(16));

	base64_encode(bytes, 16, res);

	return res;
}

void websocket_session_connect(websocket_session_t *ws)
{
	if (ws->state != WS_STATE_DISCONNECTED) {
		call_error_cb(ws, WEBSOCKET_SESSION_ERROR_STATE, "can't connect from this state: %d", ws->state);
		return;
	}

	websocket_session_setup_rng(ws);

	struct evbuffer *evb = evbuffer_new();

	evbuffer_add_printf(evb,
		"GET %s HTTP/1.1\r\n"\
		"Host: %s\r\n"\
		"Upgrade: websocket\r\n"\
		"Connection: Upgrade\r\n",
		ws->path, ws->host
	);

	if (ws->protocols) {
		evbuffer_add_printf(evb,
			"Sec-WebSocket-Protocol: %s\r\n",
			ws->protocols
		);
	}

	if (ws->origin) {
		evbuffer_add_printf(evb,
			"Origin: %s\r\n",
			ws->origin
		);
	}

	// TODO rework magic?
	free(ws->magic);
	ws->magic = websocket_session_build_magic(ws);
	evbuffer_add_printf(evb,
		"Sec-WebSocket-Key: %s\r\n"\
		"Sec-WebSocket-Version: 13\r\n"\
		"\r\n",
		ws->magic
	);

	bufferevent_write_buffer(ws->bev, evb);
	evbuffer_free(evb);

	bufferevent_setcb(ws->bev, websocket_session_init_readcb, NULL, websocket_session_evtcb, ws);
	bufferevent_enable(ws->bev, EV_READ);

	ws->state = WS_STATE_CONNECTING;
}

void *websocket_session_get_userdata(websocket_session_t *ws)
{
	return ws->ctx;
}

websocket_session_t *websocket_session_create(struct event_base *base, const char *path, const char *host, build_connection_t bc, void *bc_arg, void *ctx)
{
	websocket_session_t *res = malloc(sizeof(websocket_session_t));

	res->base = base;
	res->path = strdup(path);
	res->host = strdup(host);
	res->protocols = NULL;
	res->origin = NULL;
	res->magic = NULL;
	res->create_connection = bc;
	res->create_connection_arg = bc_arg;
	res->bev = NULL;
	res->current_content = NULL;
	res->ctx = ctx;

	res->user_messagecb = NULL;
	res->user_evtcb = NULL;
	res->user_errcb = NULL;
	res->user_dbgcb = NULL;

	res->bev = bc(bc_arg);

	res->outgoing_active = false;
	STAILQ_INIT(&res->outgoing_head);

	res->state = WS_STATE_DISCONNECTED;

	return res;
}

void websocket_session_set_protocols(websocket_session_t *ws, const char *protocols)
{
	free(ws->protocols);
	if (protocols)
		ws->protocols = strdup(protocols);
	else
		ws->protocols = NULL;
}

void websocket_session_set_origin(websocket_session_t *ws, const char *origin)
{
	free(ws->origin);
	if (origin)
		ws->origin = strdup(origin);
	else
		ws->origin = NULL;
}

void websocket_session_set_callbacks(websocket_session_t *ws, websocket_session_evtcb_t evtcb, websocket_session_errcb_t errcb, websocket_session_messagecb_t messagecb)
{
	ws->user_evtcb = evtcb;
	ws->user_errcb = errcb;
	ws->user_messagecb = messagecb;
}

void websocket_session_set_dbg_cb(websocket_session_t *ws, websocket_session_dbgcb_t dbgcb)
{
	ws->user_dbgcb = dbgcb;
}

void websocket_session_free(websocket_session_t *ws)
{
	if (ws->state == WS_STATE_CONNECTED) {
		ws->state = WS_STATE_DISCONNECTING;
	}

	if (ws->state == WS_STATE_DISCONNECTING) {
		_websocket_session_disconnect(ws, "user requested");
	}

	free(ws->path);
	free(ws->host);
	free(ws->protocols);
	free(ws->origin);
	free(ws->magic);

	free(ws);
}
