#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/http.h>

#include "event-magic/ssl.h"
#include "event-magic/http.h"

#define TEST_URI "https://www.google.de"
//#define TEST_URI "https://blog.fefe.de"
#define TEST_CA_FILE "/etc/ssl/ca-bundle.pem"
#define TEST_CA_PATH NULL//"/etc/ssl/certs/"


const char *example_configure_ssl_ctx(lew_ssl_factory_t *essl, SSL_CTX *ssl_ctx)
{
    (void) essl;

    if (SSL_CTX_load_verify_locations(ssl_ctx, TEST_CA_FILE, TEST_CA_PATH) != -1) {
        return "CTX_load_verify_locations";
    }

    return NULL;
}

void example_handle_request(struct evhttp_request *req, void *usr)
{
    (void) usr;

    if (!req) {
        fprintf(stderr, "req NULL!\n");
        // TODO what needs to be cleared?
        return;
    }

    fprintf(stderr, "req returned! COOOL\n");

    char buffer[256];
    int nread;

    fprintf(stderr, "Response line: %d %s\n",
            evhttp_request_get_response_code(req),
            evhttp_request_get_response_code_line(req));

    while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
                                    buffer, sizeof(buffer)))
           > 0) {
        /* These are just arbitrary chunks of 256 bytes.
         * They are not lines, so we can't treat them as such. */
        fwrite(buffer, nread, 1, stdout);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "need uri\n");
        exit(-1);
    }

    struct event_base *base = event_base_new();

    if (!base) {
        fprintf(stderr, "no evbase.. aborting\n");
        return EXIT_FAILURE;
    }

    struct evhttp_uri *http_uri = evhttp_uri_parse(argv[1]);

    if (!http_uri) {
        fprintf(stderr, "couldn't parse uri.. aborting\n");
        goto base_cleanup;
    }

    lew_ssl_factory_t *essl = lew_ssl_create
                      (
                          base,
                          evhttp_uri_get_host(http_uri),
                          evhttp_uri_get_port_web(http_uri),
                          NULL,
                          NULL,
                          NULL
                      );
    if (strcasecmp(evhttp_uri_get_scheme(http_uri), "https") != 0) {
        fprintf(stderr, "not really ssl-ing\n");
        lew_ssl_dont_really_ssl(essl);
    }

    http_ssl_conn_t *sslconn = http_ssl_setup(base, essl);

    struct evhttp_request *req = evhttp_request_new(example_handle_request, NULL);
    char *uri = evhttp_uri_get_path_web(http_uri);
    fprintf(stderr, "requesting %s\n", uri);
    evhttp_make_request(http_ssl_get_evhttp_con(sslconn), req, EVHTTP_REQ_GET, uri);

    event_base_dispatch(base);

    free(uri);

    evhttp_uri_free(http_uri);

    http_ssl_conn_cleanup(sslconn);

base_cleanup:
    event_base_free(base);
}
