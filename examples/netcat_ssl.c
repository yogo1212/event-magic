#include <signal.h>
#include <stdlib.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include "event-magic/ssl.h"

struct event *sig_event;
struct event_base *base;

struct bufferevent *bev_stdin, *bev_ssl;

static void cleanup(void)
{
    bufferevent_free(bev_stdin);
    bufferevent_free(bev_ssl);
}

static void stdineventcb(struct bufferevent *bev, short events, void *ptr)
{
    (void) bev;

    if (events & BEV_EVENT_CONNECTED) {
    }
    else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "error with %s: %d!\n", (char *) ptr, events);
    }
    else if (BEV_EVENT_EOF) {
        fprintf(stderr, "%s was closed: %d\n", (char *) ptr, events);
    }

    cleanup();
}

static void stdinreadcb(struct bufferevent *bev, void *ctx)
{
    (void) ctx;

    uint8_t buf[512];
    size_t rsize;

    while ((rsize = bufferevent_read(bev, buf, sizeof(buf))) > 0)
        bufferevent_write(bev_ssl, buf, rsize);
}

static void sslineventcb(struct bufferevent *bev, short events, void *ptr)
{
    (void) bev;

    if (events & BEV_EVENT_CONNECTED) {
    }
    else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "error with %s: %d!\n", (char *) ptr, events);
    }
    else if (BEV_EVENT_EOF) {
        fprintf(stderr, "%s was closed: %d\n", (char *) ptr, events);
    }

    cleanup();
}

static void sslinreadcb(struct bufferevent *bev, void *ctx)
{
    (void) ctx;

    uint8_t buf[512];
    size_t rsize;

    while ((rsize = bufferevent_read(bev, buf, sizeof(buf))) > 0)
        fwrite(buf, rsize, 1, stdout);
}

void handle_interrupt(int fd, short events, void *arg)
{
    (void) fd;
    (void) events;

    lew_ssl_factory_t *essl = arg;

    event_free(sig_event);

    //sslcleanup:
    lew_ssl_connection_cleanup(essl);
}

int main(int argc, char *argv[])
{
    base = event_base_new();

    if (!base) {
        fprintf(stderr, "no evbase.. aborting\n");
        return -1;
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: %s REMOTE PORT", argv[0]);
        return 1;
    }

    lew_ssl_factory_t *essl = lew_ssl_create
                      (
                          base,
                          argv[1],
                          atoi(argv[2]),
                          NULL,
                          NULL,
                          NULL
                      );
    lew_ssl_dont_really_ssl(essl);

    int stdinfd = fileno(stdin);
    evutil_make_socket_nonblocking(stdinfd);

    bev_stdin = bufferevent_socket_new(
                       base,
                       stdinfd,
                       BEV_OPT_DEFER_CALLBACKS
                   );

    bufferevent_setcb(bev_stdin, stdinreadcb, NULL, stdineventcb, "stdin");

    bev_ssl = lew_ssl_connect(essl);
    bufferevent_setcb(bev_ssl, sslinreadcb, NULL, sslineventcb, "ssl");

    bufferevent_enable(bev_ssl, EV_READ | EV_WRITE);
    bufferevent_enable(bev_stdin, EV_READ);

    sig_event = evsignal_new(base, SIGINT, handle_interrupt, essl);
    event_add(sig_event, NULL);

    event_base_dispatch(base);

    //base_cleanup:
    event_base_free(base);
}
