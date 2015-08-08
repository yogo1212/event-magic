#ifndef __LEW_SSL_H
#define __LEW_SSL_H

#include <stdbool.h>

#include <openssl/ssl.h>

#include <event2/event.h>
#include <event2/bufferevent.h>


struct lew_ssl_factory;
typedef struct lew_ssl_factory lew_ssl_factory_t;

typedef enum {
	// errorstr
	SSL_ERROR_INIT,
	SSL_ERROR_CONFIG,
	SSL_ERROR_DNS,
	SSL_ERROR_ALERT,
	SSL_ERROR_CONNECTION
} lew_ssl_error_t;

/* Return true if you want the library to free the struct. Return false if you want to do that yourself later */
typedef bool (*lew_ssl_error_cb_t)(lew_ssl_factory_t *essl, lew_ssl_error_t error);
/* Return NULL if everything went ok or a string containing an error */
typedef const char *(*lew_ssl_ssl_ctx_config)(lew_ssl_factory_t *essl, SSL_CTX *ssl_ctx);

lew_ssl_factory_t *lew_ssl_create(
	struct event_base *base,
	const char *hostname,
	const int port,
	void *userptr,
	lew_ssl_ssl_ctx_config configcb,
	lew_ssl_error_cb_t errorcb
);
void lew_ssl_connection_cleanup(lew_ssl_factory_t *essl);

typedef void (*lew_ssl_info_cb_t)(lew_ssl_factory_t *ess, char *msg, size_t msglen);
void lew_ssl_set_info_cb(lew_ssl_factory_t *essl, lew_ssl_info_cb_t infocb);

char *lew_ssl_get_error(lew_ssl_factory_t *essl);
void lew_ssl_dont_really_ssl(lew_ssl_factory_t *essl);

struct bufferevent *lew_ssl_connect(lew_ssl_factory_t *essl);

const char *lew_ssl_get_hostname(lew_ssl_factory_t *essl);
unsigned short lew_ssl_get_port(lew_ssl_factory_t *essl);
void *lew_ssl_get_userdata(lew_ssl_factory_t *essl);


void lew_ssl_lib_init(void);
void lew_ssl_lib_cleanup(void);

#endif
