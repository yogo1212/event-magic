#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>

#include <event2/event.h>
#include <event2/buffer.h>

#include <mqtt.h>
#include <ssl.h>

struct event_base *base;

bool ssl_errorcb(lew_ssl_t *essl, lew_ssl_error_t error)
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

/* Return NULL if everything went ok or a string containing an error */
const char *ssl_configcb(lew_ssl_t *essl, SSL_CTX *ssl_ctx)
{
    auth_data_t *data = lew_ssl_get_userdata(essl);

    if (SSL_CTX_load_verify_locations(ssl_ctx, data->ca, NULL) < 1) {
        return "ca-error!";
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, data->cert, SSL_FILETYPE_PEM) < 1) {
        return "certificate not found!";
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, data->key, SSL_FILETYPE_PEM) < 1) {
        return "private key not found!";
    }

    if (SSL_CTX_check_private_key(ssl_ctx) < 1) {
        return "invalid private key!";
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    return NULL;
}

void mqtt_msgcb(mqtt_session_t *conn, const char *topic, void *message, size_t len)
{
    printf("%s: %.*s\n", topic, (int) len, (char *) message);
}

void mqtt_errorcb(mqtt_session_t *conn, enum mqtt_session_error err)
{
    fprintf(stderr, "mqtt-error %d: %s\n", err, mqtt_session_last_error(conn));
}

void handle_interrupt(int fd, short events, void *arg)
{
    (void) fd;
    (void) events;

    struct timeval timeout = { 1 , 0 } ;
    event_base_loopexit(base, &timeout);
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, "Usage:\n%s [server] [port] [topic]\n", argv[0]);
        return 1;
    }

    char *server = argv[1];
    uint16_t port = atoi(argv[2]);
    char *topic = argv[3];

    base = event_base_new();

    if (!base) {
        fprintf(stderr, "Couldn't create event-base!\n");
        return 1;
    }

    auth_data_t miau;
    miau.cert = "/etc/x509/host.crt";
    miau.key = "/etc/x509/host.key";
    miau.ca = "/etc/airfy/ca.crt";

    lew_ssl_lib_init();

    lew_ssl_t *ssl = lew_ssl_create(
                         base,
                         server,
                         port,
                         &miau,
                         ssl_configcb,
                         ssl_errorcb
                     );

    /* SSL is still not connected - but we can start writing to the bufferevent */
    mqtt_session_t *mc = mqtt_session_setup(base, lew_ssl_reconnect, ssl, mqtt_msgcb, mqtt_errorcb, NULL);
    mqtt_session_connect(mc, "event-driven-ssl-test", true, 10, NULL, NULL);

    mqtt_session_sub(mc, topic, 1);

    event_base_dispatch(base);

mqtt_cleanup:
    mqtt_session_disconnect(mc);
    mqtt_session_cleanup(mc);

ssl_cleanup:
    lew_ssl_connection_cleanup(ssl);

base_cleanup:
    event_base_free(base);

    lew_ssl_lib_cleanup();

    return 0;
}
