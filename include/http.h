#ifndef __LEW_HTTP_H
#define __LEW_HTTP_H

/*
 * DWTFYW - DBM (TS)
 * do whatever the fuck you want with this.
 * don't blame me.
 * that simple.
 */
#include "ssl.h"

struct http_ssl_conn;
typedef struct http_ssl_conn http_ssl_conn_t;

http_ssl_conn_t *http_ssl_setup(struct event_base *base, lew_ssl_factory_t *essl);

typedef struct {
    struct evhttp_uri *http_uri;
    const char *scheme, *host, *path, *query;
    int port;
    // TODO this might be veeeeeeeeeery long
    char uri[1024];
} http_request_data_t;

http_request_data_t *parse_uri(const char *uri_str);

short
HRO_REQ_CAN_FREE_CONN = 1,
HRO_REQ_DONT_ADD_HOST_HEADER = 2;

struct http_request;
typedef struct http_request http_request_t;


typedef enum evhttp_cmd_type(*http_request_alter_func_t)(struct evhttp_request *req, void *userdata);
typedef void (*request_cb_t)(struct evhttp_request *, void *);

// this takes ownership of the ssl-bufferevent
http_request_t *http_request_make_request(http_ssl_conn_t *conn,
        short options,
        const char *uri,
        http_request_alter_func_t custom_request_func,
        request_cb_t req_cb,
        void *userdata);
void http_request_cleanup(http_request_t *request);

#endif
