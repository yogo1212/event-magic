#ifndef WEBSOCKET_H
#define WEBSOCKET_H


struct websocket_session;
typedef struct websocket_session websocket_session_t;

void websocket_session_connect(websocket_session_t *ws);
void websocket_session_disconnect(websocket_session_t *ws);

typedef enum {
	WEBSOCKET_SESSION_EVENT_CONNECTED = 1,
	WEBSOCKET_SESSION_EVENT_DISCONNECTED
// TODO ping here?
} websocket_session_event_t;
/* msg can either be the accepted protocol on connect (NULL if not present) or the reason on close */
typedef void (*websocket_session_evtcb_t)(websocket_session_t *ws, websocket_session_event_t event, const char *msg);

typedef enum {
	WEBSOCKET_SESSION_ERROR_NO_ERROR = 0,
	WEBSOCKET_SESSION_ERROR_STATE,
	WEBSOCKET_SESSION_ERROR_NETWORK,
	WEBSOCKET_SESSION_ERROR_PROTOCOL,
	WEBSOCKET_SESSION_ERROR_HANDSHAKE,
	WEBSOCKET_SESSION_ERROR_MEMORY
} websocket_session_error_t;
typedef void (*websocket_session_errcb_t)(websocket_session_t *ws, websocket_session_event_t error, const char *msg);

typedef enum {
	WEBSOCKET_SESSION_FRAME_TYPE_TEXT = 1,
	WEBSOCKET_SESSION_FRAME_TYPE_BINARY
} websocket_session_content_type;
typedef void (*websocket_session_messagecb_t)(websocket_session_t *ws, websocket_session_content_type type, struct evbuffer *evb);

/* fragment_size can be 0 */
void websocket_session_send_message(websocket_session_t *ws, websocket_session_content_type type, struct evbuffer *evb, size_t fragment_size);

void websocket_session_set_callbacks(websocket_session_t *ws, websocket_session_evtcb_t evtcb, websocket_session_errcb_t errcb, websocket_session_messagecb_t messagecb);
void websocket_session_set_protocols(websocket_session_t *ws, const char *protocols);
void websocket_session_set_origin(websocket_session_t *ws, const char *origin);

void *websocket_session_get_userdata(websocket_session_t *ws);

websocket_session_t *websocket_session_create(struct event_base *base, const char *path, const char *host, build_connection_t bc, void *bc_arg, void *ctx);
void websocket_session_free(websocket_session_t *ws);


#endif
