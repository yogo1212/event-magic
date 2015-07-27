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

http_request_data_t *parse_uri(const char *uri_str)
{
    http_request_data_t *res = malloc(sizeof(http_request_data_t));
    res->http_uri = evhttp_uri_parse(uri_str);

    if (res->http_uri == NULL) {
        fprintf(stderr, "malformed url\n");
        goto ouch;
    }

    res->scheme = evhttp_uri_get_scheme(res->http_uri);

    if (res->scheme == NULL) {
        fprintf(stderr, "url has no scheme\n");
        goto ouch;
    }

    res->host = evhttp_uri_get_host(res->http_uri);

    if (res->host == NULL) {
        fprintf(stderr, "url must have a host\n");
        goto ouch;
    }

    res->port = evhttp_uri_get_port(res->http_uri);

    if (res->port == -1) {
        res->port = (strcasecmp(res->scheme, "http") == 0) ? 80 : 443;
    }

    res->path = evhttp_uri_get_path(res->http_uri);

    if (res->path == NULL) {
        res->path = "/";
    }

    res->query = evhttp_uri_get_query(res->http_uri);

    if (res->query == NULL) {
        snprintf(res->uri, sizeof(res->uri) - 1, "%s", res->path);
    }
    else {
        snprintf(res->uri, sizeof(res->uri) - 1, "%s?%s", res->path, res->query);
    }

    res->uri[sizeof(res->uri) - 1] = '\0';

    return res;

ouch:

    if (res->http_uri) {
        evhttp_uri_free(res->http_uri);
    }

    free(res);
    return NULL;
}




struct http_request {
    http_ssl_conn_t *sslconn;
    struct evhttp_request *req;
    short options;
    void *userdata;
};

http_request_t *http_request_make_request(http_ssl_conn_t *conn,
        short options,
        const char *uri,
        http_request_alter_func_t custom_request_func,
        request_cb_t req_cb,
        void *userdata)
{
    http_request_t *res = malloc(sizeof(http_request_t));
    res->options = options;
    res->sslconn = conn;
    res->userdata = userdata;

    res->req = evhttp_request_new(req_cb, userdata);

    struct evkeyvalq *output_headers = evhttp_request_get_output_headers(res->req);

    if (res->options & HRO_REQ_DONT_ADD_HOST_HEADER) {
        evhttp_add_header(output_headers, "Host", lew_ssl_get_hostname(conn->essl));
    }

    enum evhttp_cmd_type req_type = EVHTTP_REQ_GET;

    if (custom_request_func) {
        req_type = custom_request_func(res->req, userdata);
    }

    evhttp_make_request(conn->evhttpcon, res->req, req_type, uri);

    return res;
}

void http_request_cleanup(http_request_t *request)
{
    if (request->options & HRO_REQ_CAN_FREE_CONN) {
        http_ssl_conn_cleanup(request->sslconn);
    }

    free(request);
}
