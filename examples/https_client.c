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

//#define TEST_URI "https://www.google.de"
#define TEST_URI "https://blog.fefe.de"
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
    (void) argc;
    (void) argv;

    struct event_base *base = event_base_new();

    if (!base) {
        fprintf(stderr, "no evbase.. aborting\n");
        return EXIT_FAILURE;
    }

    http_request_data_t *hrd = parse_uri(TEST_URI);

    if (!hrd) {
        fprintf(stderr, "couldn't parse uri.. aborting\n");
        goto base_cleanup;
    }

    lew_ssl_factory_t *essl = lew_ssl_create
                      (
                          base,
                          hrd->host,
                          hrd->port,
                          NULL,
                          NULL,
                          NULL
                      );

    http_ssl_conn_t *sslconn = http_ssl_setup(base, essl);

    http_request_t *request = http_request_make_request(sslconn, HRO_REQ_CAN_FREE_CONN, hrd->uri, NULL, example_handle_request, NULL);

    event_base_dispatch(base);

    //request_cleanup:
    http_request_cleanup(request);

    //hrd_cleanup:
    free(hrd);

base_cleanup:
    event_base_free(base);
}
