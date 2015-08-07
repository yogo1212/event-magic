#ifndef __LEW_HTTP_H
#define __LEW_HTTP_H

/*
 * DWTFYW - DBM (TS)
 * do whatever the fuck you want with this.
 * don't blame me.
 * that simple.
 */
#include "event-magic/ssl.h"

uint16_t evhttp_uri_get_port_web(struct evhttp_uri *http_uri);
/* You need to free the result! */
char *evhttp_uri_get_path_web(struct evhttp_uri *http_uri);

struct http_ssl_conn;
typedef struct http_ssl_conn http_ssl_conn_t;

http_ssl_conn_t *http_ssl_setup(struct event_base *base, lew_ssl_factory_t *essl);
void http_ssl_conn_cleanup(http_ssl_conn_t *sslconn);

struct evhttp_connection *http_ssl_get_evhttp_con(http_ssl_conn_t *con);

#define http_ssl_conn_add_host_to_request(conn, req) evhttp_add_header(evhttp_request_get_output_headers(req), "Host", lew_ssl_get_hostname(conn->essl))

#endif
