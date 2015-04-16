#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/x509.h>

#include <event2/bufferevent_ssl.h>

#include <event2/dns.h>

#include "openssl_hostname_validation.h"

#include "ssl.h"

enum LEW_SSL_STATE {
    SSL_STATE_PREPARING,
    SSL_STATE_CONNECTING,
    SSL_STATE_CONNECTED,
    SSL_STATE_ERROR
};

struct lew_ssl_factory {
    char hostname[257];
    int port;

    bool dont_ssl;

    //TODO maybe heap is better w/ realloc
    char error[1024];
    size_t errorlen;
    lew_ssl_error_cb_t errorcb;
    enum LEW_SSL_STATE state;

    lew_ssl_info_cb_t infocb;

    SSL_CTX *ssl_ctx;

    struct bufferevent *bev;

    void *userptr;
    struct evdns_base *dns_base;
    struct event_base *base;
};

static int ex_data_index;

const char *lew_ssl_get_hostname(lew_ssl_factory_t *essl)
{
    return essl->hostname;
}

unsigned short lew_ssl_get_port(lew_ssl_factory_t *essl)
{
    return essl->port;
}

void lew_ssl_set_info_cb(lew_ssl_factory_t *essl, lew_ssl_info_cb_t infocb)
{
    essl->infocb = infocb;
}

void lew_ssl_dont_really_ssl(lew_ssl_factory_t *essl)
{
    essl->dont_ssl = true;
}

static void lew_ssl_collectSSLerr(lew_ssl_factory_t *essl, const char *prefix);
static bool lew_ssl_call_errorcb(lew_ssl_factory_t *essl, lew_ssl_error_t error);
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg);

static void ssl_dns_callback(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
    lew_ssl_factory_t *essl = ptr;

    if (errcode) {
        essl->errorlen = snprintf(essl->error, sizeof(essl->error), "couldn't resolve");
        lew_ssl_call_errorcb(essl, SSL_ERROR_DNS);
        essl->state = SSL_STATE_ERROR;
    }
    else {
        if (addr->ai_family == AF_INET) {
            ((struct sockaddr_in *) addr->ai_addr)->sin_port = htons(essl->port);
        }
        else if (addr->ai_family == AF_INET6) {
            ((struct sockaddr_in6 *) addr->ai_addr)->sin6_port = htons(essl->port);
        }
        else {
            essl->errorlen = snprintf(essl->error, sizeof(essl->error), "unknown ai_family: %d", addr->ai_family);
            lew_ssl_call_errorcb(essl, SSL_ERROR_DNS);
            goto end;
        }

        //add the port and - voila
        bufferevent_socket_connect(essl->bev, addr->ai_addr, addr->ai_addrlen);
end:
        evutil_freeaddrinfo(addr);
        essl->state = SSL_STATE_CONNECTED;
    }

    evdns_base_free(essl->dns_base, 0);
    essl->dns_base = NULL;
    essl->bev = NULL;
}

static bool default_ssl_info_handler(lew_ssl_factory_t *essl, lew_ssl_error_t error)
{
    fprintf(stderr, "ERROR: ");

    if (error == SSL_ERROR_INIT) {
        fprintf(stderr, "SSL_INIT %s", lew_ssl_get_error(essl));
    }
    else if (error == SSL_ERROR_CONNECTION) {
        fprintf(stderr, "SSL_CONNECTION %s", lew_ssl_get_error(essl));
    }
    else {
        fprintf(stderr, "unknown error!!");
    }

    fprintf(stderr, "\n");
    return true;
}

void handle_opensll_error(const SSL *ssl, int type, int val)
{
    lew_ssl_factory_t *essl = SSL_get_ex_data(ssl, ex_data_index);

    if (!essl->infocb) {
        return;
    }

    const char *str;

    int w;

    w = type & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT) {
        str = "SSL_connect";
    }
    else if (w & SSL_ST_ACCEPT) {
        str = "SSL_accept";
    }
    else {
        str = "undefined";
    }

    size_t infolen;
    char info[1024];

    if (type & SSL_CB_LOOP) {
        infolen = snprintf(info, sizeof(info) - 1, "%s: %s", str, SSL_state_string_long(ssl));
        info[sizeof(info) - 1] = '\0';
        essl->infocb(essl, info, infolen);
    }
    else if (type & SSL_CB_ALERT) {

        str = (type & SSL_CB_READ) ? "read" : "write";
        infolen = snprintf(info, sizeof(info) - 1, "SSL3 alert %s: %s:%s\n",
                           str,
                           SSL_alert_type_string_long(val),
                           SSL_alert_desc_string_long(val));
        info[sizeof(info) - 1] = '\0';
        essl->infocb(essl, info, infolen);
    }
    else if (type & SSL_CB_EXIT) {

        if (val == 0) {
            infolen = snprintf(info, sizeof(info) - 1, "%s: failed in %s\n",
                               str, SSL_state_string_long(ssl));
            info[sizeof(info) - 1] = '\0';
            essl->infocb(essl, info, infolen);
        }
        else if (val < 0) {
            infolen = snprintf(info, sizeof(info) - 1, "%s: error in %s\n",
                               str, SSL_state_string_long(ssl));
            info[sizeof(info) - 1] = '\0';
            essl->infocb(essl, info, infolen);
        }

    }
}

struct bufferevent *lew_ssl_connect(lew_ssl_factory_t *essl)
{
    if (essl->bev) {
        return NULL;
    }

    if (essl->dont_ssl) {
        essl->bev = bufferevent_socket_new(essl->base, -1, BEV_OPT_CLOSE_ON_FREE);
    }
    else {
        SSL *ssl;
        ssl = SSL_new(essl->ssl_ctx);

        if (ssl == NULL) {
            lew_ssl_collectSSLerr(essl, "SSL_new");

            if (lew_ssl_call_errorcb(essl, SSL_ERROR_INIT)) {
                return NULL;
            }
        }

        SSL_set_ex_data(ssl, ex_data_index, essl);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        // Set hostname for SNI extension
        SSL_set_tlsext_host_name(ssl, essl->hostname);
#endif

        essl->bev = bufferevent_openssl_socket_new(essl->base, -1, ssl,
                    BUFFEREVENT_SSL_CONNECTING,
                    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

        bufferevent_openssl_set_allow_dirty_shutdown(essl->bev, 1);
    }

    essl->state = SSL_STATE_CONNECTING;

    // spawn dns-lookup
    essl->dns_base = evdns_base_new(essl->base, EVDNS_BASE_INITIALIZE_NAMESERVERS);

    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    /* Unless we specify a socktype, we'll get at least two entries for
     * each address: one for TCP and one for UDP. That's not what we
     * want. */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    evdns_getaddrinfo(essl->dns_base, essl->hostname, NULL,
                      &hints, ssl_dns_callback, essl);

    return essl->bev;
}

lew_ssl_factory_t *lew_ssl_create(
    struct event_base *base,
    const char *hostname,
    const int port,
    void *userptr,
    lew_ssl_ssl_ctx_config configcb,
    lew_ssl_error_cb_t errorcb
)
{
    lew_ssl_lib_init();

    lew_ssl_factory_t *res = malloc(sizeof(lew_ssl_factory_t));
    res->base = base;
    res->errorlen = 0;
    res->state = SSL_STATE_PREPARING;
    res->dont_ssl = false;

    if (errorcb) {
        res->errorcb = errorcb;
    }
    else {
        res->errorcb = default_ssl_info_handler;
    }

    res->infocb = NULL;

    strncpy(res->hostname, hostname, sizeof(res->hostname));
    res->port = port;

    res->ssl_ctx = NULL;
    res->bev = NULL;
    res->userptr = userptr;

    res->dns_base = NULL;

    /* Create a new OpenSSL context */
    res->ssl_ctx = SSL_CTX_new(SSLv23_method());

    if (!res->ssl_ctx) {
        lew_ssl_collectSSLerr(res, "CTX_new");

        if (lew_ssl_call_errorcb(res, SSL_ERROR_INIT)) {
            res = NULL;
            goto end;
        }
    }

    /*
     * This does default checks AND checks whether the certificate
     * is actually for the host we're connecting to.
     */
    SSL_CTX_set_cert_verify_callback(res->ssl_ctx, cert_verify_callback, res);

    if (configcb) {
        const char *err = configcb(res, res->ssl_ctx);

        if (err) {
            strncpy(res->error, err, sizeof(res->error));
            res->error[sizeof(res->error) - 1] = '\0';

            if (lew_ssl_call_errorcb(res, SSL_ERROR_CONFIG)) {
                res = NULL;
                goto end;
            }
        }
    }

    SSL_CTX_set_info_callback(res->ssl_ctx, handle_opensll_error);

end:
    return res;
}

static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
    lew_ssl_factory_t *essl = (lew_ssl_factory_t *) arg;
    HostnameValidationResult res = Error;

    X509 *server_cert = NULL;
    server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

    char cert_str[256];

    const char *res_str = NULL;

    if (!server_cert) {
        strncpy(cert_str, "current cert NULL!", sizeof(cert_str) - 1);
        goto leave;
    }

    X509_NAME_oneline(X509_get_subject_name(server_cert), cert_str,
                          sizeof(cert_str));

    if (X509_verify_cert(x509_ctx) <= 0) {
        res_str = X509_verify_cert_error_string(x509_ctx->error);

        goto leave;
    }

    res = validate_hostname(essl->hostname, server_cert);

    switch (res) {
    case MatchFound:
        break;

    case MatchNotFound:
        res_str = "MatchNotFound";
        break;

    case NoSANPresent:
        res_str = "NoSANPresent";
        break;

    case MalformedCertificate:
        res_str = "MalformedCertificate";
        break;

    case Error:
        res_str = "Error";
        break;

    default:
        res_str = "WTF!";
        break;
    }


    if (res == MatchFound) {
        return 1;
    }
leave:
    cert_str[sizeof(cert_str) - 1] = '\0';

    //X509_STORE_CTX_get_error(x509_ctx)

    essl->errorlen = snprintf(essl->error, sizeof(essl->error) - 1, "validating '%s' failed at '%s': '%s'", essl->hostname, cert_str, res_str);
    essl->error[sizeof(essl->error) - 1] = '\0';

    if (essl->errorcb) {
        essl->errorcb(essl, SSL_ERROR_INIT);
    }

    return 0;
}

static bool lew_ssl_call_errorcb(lew_ssl_factory_t *essl, lew_ssl_error_t error)
{
    // TODO is this smart or not?
    bool res = true;

    if (essl->errorcb) {
        res = essl->errorcb(essl, error);
    }

    if (res) {
        lew_ssl_connection_cleanup(essl);
    }

    return res;
}

void lew_ssl_connection_cleanup(lew_ssl_factory_t *essl)
{
    if (!essl) {
        return;
    }

    if (essl->dns_base) {
        evdns_base_free(essl->dns_base, 0);
    }

    /*
     * This will probably be done already by the bufferevent-destructor
     * if (essl->ssl) {
     *     SSL_shutdown(essl->ssl);
     *     SSL_free(essl->ssl);
     * }
     */

    if (essl->ssl_ctx) {
        SSL_CTX_free(essl->ssl_ctx);
    }

    free(essl);

    lew_ssl_lib_cleanup();
}

static int libevent_ssl_SSL_error_cb(const char *str, size_t len, void *u)
{
    lew_ssl_factory_t *essl = (lew_ssl_factory_t *) u;

    if ((essl->errorlen + len) >= sizeof(essl->error)) {
        len = sizeof(essl->error) - essl->errorlen - 1;
    }

    if (len != 0) {
        strncpy(&essl->error[essl->errorlen], str, len);
        essl->errorlen += len;
    }

    return len;
}

static void lew_ssl_collectSSLerr(lew_ssl_factory_t *essl, const char *prefix)
{
    if (essl->errorlen >= strlen(prefix)) {
        essl->errorlen = sizeof(essl->error) - 1;
    }
    else {
        essl->errorlen = strlen(prefix);
    }

    if (essl->errorlen != 0) {
        strncpy(&essl->error[0], prefix, essl->errorlen);
    }

    ERR_print_errors_cb(libevent_ssl_SSL_error_cb, essl);
    essl->error[essl->errorlen] = '\0';
}

void *lew_ssl_get_userdata(lew_ssl_factory_t *essl)
{
    return essl->userptr;
}

char *lew_ssl_get_error(lew_ssl_factory_t *essl)
{
#if 0
    int errcode = EVUTIL_SOCKET_ERROR();

    /* Print out the OpenSSL error queue that libevent
     * squirreled away for us, if any. */
    while ((oslerr = bufferevent_get_openssl_error(bev))) {
        ERR_error_string_n(oslerr, buffer, sizeof(buffer));
        fprintf(stderr, "%s\n", buffer);
        printed_err = 1;
    }

    /* If the OpenSSL error queue was empty, maybe it was a
     * socket error; let's try printing that. */
    if (! printed_err)
        fprintf(stderr, "socket error = %s (%d)\n",
                evutil_socket_error_to_string(errcode),
                errcode);

    return;
#endif
    return essl->error;
}

static size_t lib_users = 0;

void lew_ssl_lib_init(void)
{
    lib_users++;

    if (lib_users > 1) {
        return;
    }

    // Initialize OpenSSL
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ex_data_index = SSL_get_ex_new_index(0, "lew_ssl", NULL, NULL, NULL);
}

void lew_ssl_lib_cleanup(void)
{
    lib_users--;

    if (lib_users > 0) {
        return;
    }

    //CONF_modules_free();
    ERR_remove_state(0);
    //ENGINE_cleanup();
    //CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}
