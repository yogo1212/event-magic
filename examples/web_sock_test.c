#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/err.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "event-magic/ssl.h"
#include "event-magic/websocket.h"

struct event_base *base;

void chat_evtcb(websocket_session_t *ws, websocket_session_event_t event, const char *msg)
{
	(void) ws;

	struct evbuffer *evb;

	fprintf(stderr, "event: %d: %s\n", event, msg);
	switch (event) {
		case WEBSOCKET_SESSION_EVENT_CONNECTED:
			evb = evbuffer_new();
			evbuffer_add_printf(evb, "Hiho");
			websocket_session_send_message(ws, WEBSOCKET_SESSION_FRAME_TYPE_TEXT, evb, 0);
			evbuffer_free(evb);
			break;
		case WEBSOCKET_SESSION_EVENT_DISCONNECTED: break;
	}
}

void chat_errcb(websocket_session_t *ws, websocket_session_event_t error, const char *msg)
{
	(void) ws;

	fprintf(stderr, "error: %d: %s\n", error, msg);
}

void chat_messagecb(websocket_session_t *ws, websocket_session_content_type type, struct evbuffer *evb)
{
	(void) ws;

	if (type == WEBSOCKET_SESSION_FRAME_TYPE_TEXT) {
		char buf[512];
		int readlen;
		printf("received: ");
		while ((readlen = evbuffer_remove(evb, buf, sizeof(buf))) > 1) {
			printf("%.*s", readlen, buf);
		}
		printf("\n");
		if (strncmp(buf, "That's what she said", strlen("That's what she said")) != 0) {
			struct evbuffer *reply = evbuffer_new();
			evbuffer_add_printf(reply, "SHUT UP!");
			websocket_session_send_message(ws, WEBSOCKET_SESSION_FRAME_TYPE_TEXT, reply, 0);
			evbuffer_drain(reply, evbuffer_get_length(reply));
			evbuffer_add_printf(reply, "Really!");
			websocket_session_send_message(ws, WEBSOCKET_SESSION_FRAME_TYPE_TEXT, reply, 0);
			evbuffer_free(reply);
		}
	}
	else if (type == WEBSOCKET_SESSION_FRAME_TYPE_BINARY) {
		fprintf(stderr, "received binary frame. length: %zu\n", evbuffer_get_length(evb));
	}
}


struct event *sig_event;

bool ssl_errorcb(lew_ssl_factory_t *essl, lew_ssl_error_t error)
{
	fprintf(stderr, "ssl-error %d: %s\n", error, lew_ssl_get_error(essl));

	event_base_loopexit(base, NULL);
	return false;
}


typedef struct {
	char *cert;
	char *key;
	char *ca;
} auth_data_t;

typedef struct {
	bool verbose;
	bool reconnect;
	bool ssl;
	bool debug;
	bool sub_verbose;
} sub_config_t;

/* Return NULL if everything went ok or a string containing an error */
const char *ssl_configcb(lew_ssl_factory_t *essl, SSL_CTX *ssl_ctx)
{
	auth_data_t *data = lew_ssl_get_userdata(essl);

	if (data->ca)
		if (SSL_CTX_load_verify_locations(ssl_ctx, data->ca, NULL) < 1) {
			return "ca-error!";
		}

	if (data->cert)
		if (SSL_CTX_use_certificate_file(ssl_ctx, data->cert, SSL_FILETYPE_PEM) < 1) {
			return "certificate not found!";
		}

	if (data->key) {
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, data->key, SSL_FILETYPE_PEM) < 1) {
			return "private key not found!";
		}

		if (SSL_CTX_check_private_key(ssl_ctx) < 1) {
			return "invalid private key!";
		}
	}

	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

	return NULL;
}

void handle_interrupt(int fd, short events, void *arg)
{
	(void) fd;
	(void) events;
	(void) arg;

	struct timeval timeval = { 1, 0 };
	event_base_loopexit(base, &timeval);
	event_free(sig_event);
}

void print_usage(void)
{
	fprintf(stderr, "Usage:\n[-a CA_FILE]\n[-k KEY_FILE]\n[-c CERT_FILE]\n"\
	        "[-(no-ss)l] (don't use SSL)\n[-h(elp)]\n[-r(econnect)]\n"\
	        "-s REMOTE_HOST\n-p PORT\n-w NAME (of the websocket e.g. /websocket)\n[-q PROTOCOL]\n[-o ORIGIN]\n");
}

int main(int argc, char *argv[])
{
	char *server = NULL;
	uint16_t port = 0;
	char *origin = NULL;
	char *protocols = NULL;
	char *ws_name = NULL;

	auth_data_t miau;
	miau.cert = NULL;
	miau.key = NULL;
	miau.ca = NULL;

	sub_config_t cfg;
	cfg.verbose = true;
	cfg.ssl = true;
	cfg.sub_verbose = false;
	cfg.debug = false;

	{
		opterr = 0;
		int c;

		while ((c = getopt(argc, argv, "a:k:c:s:p:w:q:o:dlrh")) != -1) {
			switch (c) {
				case 'a':
					miau.ca = optarg;
					break;

				case 'k':
					miau.key = optarg;
					break;

				case 'c':
					miau.cert = optarg;
					break;

				case 's':
					server = optarg;
					break;

				case 'p':
					port = atoi(optarg);
					break;

				case 'w':
					ws_name = optarg;
					break;

				case 'q':
					protocols = optarg;
					break;

				case 'o':
					origin = optarg;
					break;

				case 'd':
					cfg.debug = true;
					break;

				case 'r':
					cfg.reconnect = true;
					break;

				case 'l':
					cfg.ssl = false;
					break;

				case 'h':
					print_usage();
					return 0;

				case '?':
					if (isprint(optopt)) {
						fprintf(stderr, "unknown option `-%c'\n", optopt);
					}
					else {
						fprintf(stderr, "unknown option character `\\x%x'\n", optopt);
					}

					return 1;

				default:
					abort();
			}
		}
	}

	if (!server || (port == 0) || !ws_name) {
		print_usage();
		return 1;
	}

	base = event_base_new();

	if (!base) {
		fprintf(stderr, "Couldn't create event-base!\n");
		return 1;
	}

	lew_ssl_factory_t *ssl = lew_ssl_create(
			base,
			server,
			port,
			&miau,
			ssl_configcb,
			ssl_errorcb
		         );

	if (!cfg.ssl) {
		lew_ssl_dont_really_ssl(ssl);
	}

	/* SSL is still not connected - but we can start writing to the bufferevent */
	websocket_session_t *ws = websocket_session_create(base, ws_name, server, (build_connection_t) lew_ssl_connect, ssl, &cfg);
	websocket_session_set_origin(ws, origin);
	websocket_session_set_origin(ws, protocols);
	websocket_session_set_callbacks(ws, chat_evtcb, chat_errcb, chat_messagecb);
	websocket_session_connect(ws);

	if (cfg.debug) {
		//websocket_session_set_notification_cb(mc, notif_cb);
	}


	sig_event = evsignal_new(base, SIGINT, handle_interrupt, NULL);
	event_add(sig_event, NULL);

	event_base_dispatch(base);

	websocket_session_disconnect(ws);

	websocket_session_free(ws);

	lew_ssl_connection_cleanup(ssl);

	event_base_free(base);

	return 0;
}
