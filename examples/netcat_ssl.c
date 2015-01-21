#include <stdlib.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include "ssl.h"


typedef struct {
    struct evbuffer *ssloutbuffer;
    int stdoutfd;
    struct bufferevent *stdinevent;
    struct bufferevent *sslinevent;
} data_exchange_clamp_t;

static void do_the_cleanup(data_exchange_clamp_t *bla)
{
    bufferevent_free(bla->stdinevent);
    bufferevent_free(bla->sslinevent);
}


void stdineventcb(struct bufferevent *bev, short events, void *ptr)
{
    if (events & BEV_EVENT_CONNECTED) {
    }
    else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "stdinerror!\n");
        do_the_cleanup(ptr);
    }
    else if (BEV_EVENT_EOF) {
        fprintf(stderr, "stdin was closed.\n");
        do_the_cleanup(ptr);
    }
}

void stdinreadcb(struct bufferevent *bev, void *ctx)
{
    data_exchange_clamp_t *c = (data_exchange_clamp_t *) ctx;
    evbuffer_add_buffer(c->ssloutbuffer, bufferevent_get_output(bev));
}

void sslineventcb(struct bufferevent *bev, short events, void *ptr)
{
    if (events & BEV_EVENT_CONNECTED) {
    }
    else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "sslinerror!\n");
        do_the_cleanup(ptr);
    }
    else if (BEV_EVENT_EOF) {
        fprintf(stderr, "sslin was closed.\n");
        do_the_cleanup(ptr);
    }
}

void sslinreadcb(struct bufferevent *bev, void *ctx)
{
    data_exchange_clamp_t *c = (data_exchange_clamp_t *) ctx;
    evbuffer_write(bufferevent_get_output(bev), c->stdoutfd);
}

int main(int argc, char *argv[])
{
    struct event_base *base = event_base_new();

    if (!base) {
        fprintf(stderr, "no evbase.. aborting\n");
        return -1;
    }

    lew_ssl_t *essl = lew_ssl_create
                      (
                          base,
                          argv[1],
                          atoi(argv[2]),
                          NULL,
                          NULL,
                          NULL
                      );

    data_exchange_clamp_t c;

    int stdinfd = fileno(stdin);
    c.stdoutfd = fileno(stdout);
    evutil_make_socket_nonblocking(stdinfd);

    c.stdinevent = bufferevent_socket_new(
                       base,
                       stdinfd,
                       BEV_OPT_DEFER_CALLBACKS
                   );

    bufferevent_setcb(c.stdinevent, stdinreadcb, NULL, stdineventcb, &c);

    c.sslinevent = lew_ssl_extract_bev(essl);
    bufferevent_setcb(c.sslinevent, sslinreadcb, NULL, sslineventcb, &c);

    c.ssloutbuffer = bufferevent_get_output(c.sslinevent);

    bufferevent_enable(c.sslinevent, EV_READ);
    bufferevent_enable(c.stdinevent, EV_READ);

    //TODO signal-handler

    event_base_dispatch(base);

    //sslcleanup:
    lew_ssl_connection_cleanup(essl);

    //base_cleanup:
    event_base_free(base);
}
