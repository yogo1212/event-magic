#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/http.h>

#include "event-magic/http.h"

struct http_ssl_conn {
    lew_ssl_factory_t *essl;
    struct evhttp_connection *evhttpcon;
};

void http_ssl_conn_cleanup(http_ssl_conn_t *sslconn)
{
    //bufferevent_free(evhttp_connection_get_bufferevent(sslconn->evhttpcon));
    evhttp_connection_free(sslconn->evhttpcon);
    lew_ssl_connection_cleanup(sslconn->essl);

    free(sslconn);
}

http_ssl_conn_t *http_ssl_setup(struct event_base *base, lew_ssl_factory_t *essl)
{
    http_ssl_conn_t *res = malloc(sizeof(http_ssl_conn_t));

    res->essl = essl;
    // TODO blocking DNS!
    res->evhttpcon = evhttp_connection_base_bufferevent_new(base, NULL,
                     lew_ssl_connect(essl),
                     lew_ssl_get_hostname(essl),
                     lew_ssl_get_port(essl));

    return res;
}

struct evhttp_connection *http_ssl_get_evhttp_con(http_ssl_conn_t *con)
{
    return con->evhttpcon;
}

uint16_t evhttp_uri_get_port_web(struct evhttp_uri *http_uri)
{
    int port = evhttp_uri_get_port(http_uri);
    if (port > -1)
        return port;

    const char *scheme = evhttp_uri_get_scheme(http_uri);
    if (strcasecmp(scheme, "http") == 0)
        return 80;

    if (strcasecmp(scheme, "https") == 0)
        return 443;

    return 0;
}

char *evhttp_uri_get_path_web(struct evhttp_uri *http_uri)
{
    const char *path = evhttp_uri_get_path(http_uri);

    if ((path == NULL) || (strlen(path) == 0)) {
        path = "/";
    }

    const char *query = evhttp_uri_get_query(http_uri);

    char *res;
    if (query == NULL) {
        res = strdup(path);
    }
    else {
        res = malloc(strlen(path) + strlen(query) + 2);
        sprintf(res, "%s?%s", path, query);
    if (!(res->options & HRO_REQ_DONT_ADD_HOST_HEADER)) {
    }

    return res;
}
