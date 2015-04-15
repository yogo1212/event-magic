#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/err.h>

#include <event2/event.h>
#include <event2/buffer.h>

#include "mqtt.h"
#include "mqtt_util.h"
#include "ssl.h"

struct event_base *base;
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
    mqtt_subscription_engine_t *sub_engine;
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

void mqtt_msgcb(mqtt_session_t *conn, const char *topic, void *message, size_t len)
{
    sub_config_t *cfg = mqtt_session_userdata(conn);
    if (cfg->verbose)
        printf("%s: ", topic);
    printf("%.*s\n", (int) len, (char *) message);
}

void mqtt_errorcb(mqtt_session_t *conn, enum mqtt_session_error err, char *errormsg)
{
    fprintf(stderr, "mqtt-error %d: %s\n", err, errormsg);
}

void mqtt_evtcb(mqtt_session_t *conn, enum mqtt_session_event evt)
{
    sub_config_t *cfg;
    switch (evt) {
    case MQTT_EVENT_CONNECTED:
        cfg = mqtt_session_userdata(conn);
        mqtt_subscription_engine_resub(cfg->sub_engine);
        break;
    case MQTT_EVENT_DISCONNECTED:
        break;
    default:
        ;
    }
}

void handle_interrupt(int fd, short events, void *arg)
{
    (void) fd;
    (void) events;

    mqtt_session_disconnect(arg);
    event_free(sig_event);
}

void print_usage(void)
{
    fprintf(stderr, "Usage: [-a CA_FILE] [-k KEY_FILE] [-c CERT_FILE] [-n(on-verbose)] [-(no-ss)l] [-h(elp)] [-r(econnect)] -s REMOTE_HOST -p PORT -t TOPIC\n");
}

int main(int argc, char *argv[])
{
    char *server = NULL;
    uint16_t port = 0;
    char *topic = NULL;

    auth_data_t miau;
    miau.cert = NULL;
    miau.key = NULL;
    miau.ca = NULL;

    sub_config_t cfg;
    cfg.verbose = true;
    cfg.ssl = true;

    {
        opterr = 0;
        int c;
        while ((c = getopt (argc, argv, "a:k:c:s:p:t:nlrh")) != -1)
        {
            switch (c)
            {
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
            case 't':
                topic = optarg;
                break;
            case 'n':
                cfg.verbose = false;
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
                if (isprint(optopt))
                    fprintf (stderr, "unknown option `-%c'\n", optopt);
                else
                    fprintf (stderr, "unknown option character `\\x%x'\n", optopt);
                return 1;
            default:
                abort();
            }
        }
    }

    if (!server || (port == 0) || !topic) {
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

    if (!cfg.ssl)
        lew_ssl_dont_really_ssl(ssl);

    /* SSL is still not connected - but we can start writing to the bufferevent */
    mqtt_session_t *mc = mqtt_session_create(base, cfg.reconnect ? MQTT_SESSION_OPT_AUTORECONNECT : 0, mqtt_errorcb, &cfg);

    mqtt_session_setup(mc, (build_connection_t) lew_ssl_connect, ssl);
    mqtt_session_connect(mc, "event-driven-ssl-test", true, 10, NULL, NULL);
    mqtt_session_set_event_cb(mc, mqtt_evtcb);

    cfg.sub_engine = mqtt_subscription_engine_new(mc);

    mqtt_subscription_engine_sub(cfg.sub_engine, topic, 1, mqtt_msgcb, NULL);

    sig_event = evsignal_new(base, SIGINT, handle_interrupt, mc);
    event_add(sig_event, NULL);

    event_base_dispatch(base);

mqtt_cleanup:
    mqtt_session_cleanup(mc);

ssl_cleanup:
    lew_ssl_connection_cleanup(ssl);

base_cleanup:
    event_base_free(base);

    return 0;
}
