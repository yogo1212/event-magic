#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/buffer.h>

#include "mqtt_proto.h"
#include "uthash.h"

#include "event-magic/mqtt.h"

enum MQTT_STATE {
    //MQTT_STATE_INVALID = 0,
    MQTT_STATE_PREPARING,
    MQTT_STATE_CONNECTING,
    MQTT_STATE_CONNECTED,
    MQTT_STATE_DISCONNECTING,
    MQTT_STATE_DISCONNECTED,
    MQTT_STATE_ERROR
};

struct mqtt_retransmission;
typedef struct mqtt_retransmission mqtt_retransmission_t;

struct mqtt_session {
    struct event_base *base;
    struct bufferevent *bev;
    build_connection_t conn_builder;
    void *conn_state;
    void *userdata;
    bool awaiting_ping;
    struct event *timeout_evt;
    enum MQTT_STATE state;
    uint16_t next_mid;
    mqtt_retransmission_t *active_transmissions;
    mqtt_connect_data_t data;
    mqtt_session_message_handler_t msg_cb;
    void* msg_cb_arg;
    mqtt_session_error_handler_t error_cb;
    mqtt_session_notification_handler_t debug_cb;
    mqtt_session_event_handler_t event_cb;
    uint8_t options;
};

struct mqtt_retransmission {
    void *buffer;
    size_t len;
    uint16_t mid;
    struct event *evt;
    struct timeval tvl;
    mqtt_session_t *session;

    UT_hash_handle hh;
};

static void retransmission_timeout(int fd, short evt, void *arg)
{
    (void) fd;
    (void) evt;
    mqtt_retransmission_t *r = arg;

    if (r->session->state == MQTT_STATE_CONNECTED)
        bufferevent_write(r->session->bev, r->buffer, r->len);

    r->tvl.tv_sec = r->tvl.tv_sec + 1;
    if (r->tvl.tv_sec >= 12)
        r->tvl.tv_sec = 1;
    event_add(r->evt, &r->tvl);
}

static mqtt_retransmission_t *mqtt_retransmission_new(mqtt_session_t *session, void *data, size_t datalen, uint16_t mid) {
    mqtt_retransmission_t *res = malloc(sizeof(mqtt_retransmission_t));

    res->session = session;

    res->len = datalen;
    res->buffer = malloc(datalen);
    memcpy(res->buffer, data, datalen);

    res->evt = event_new(session->base, -1, EV_TIMEOUT, retransmission_timeout, res);
    res->tvl.tv_usec = 0;
    res->tvl.tv_sec = 0;

    res->mid = mid;

    if (res->session->state == MQTT_STATE_CONNECTED)
        event_add(res->evt, &res->tvl);

    // set the dup-flag
    uint8_t *cpyptr = res->buffer;
    // TODO ? shift + and ?
    *cpyptr |= ((1 << 3) & 0x8);

    return res;
}

static void mqtt_retransmission_free(mqtt_retransmission_t *r) {
    free(r->buffer);
    event_free(r->evt);

    free(r);
}

static void mqtt_retransmission_resume(mqtt_retransmission_t *r) {
    if (r->session->state == MQTT_STATE_CONNECTED)
        event_add(r->evt, &r->tvl);
}

static void mqtt_retransmission_pause(mqtt_retransmission_t *r) {
    event_del(r->evt);
}

static void add_retransmission(mqtt_session_t *mc, struct evbuffer *evb, uint16_t mid)
{
    size_t evblen = evbuffer_get_length(evb);
    void *evbbuf = alloca(evblen);
    evbuffer_copyout(evb, evbbuf, evblen);
    mqtt_retransmission_t *r = mqtt_retransmission_new(mc, evbbuf, evblen, mid);

    if (mc->state != MQTT_STATE_CONNECTED)
        mqtt_retransmission_pause(r);

    mqtt_retransmission_t *tmp;
    HASH_REPLACE(hh, mc->active_transmissions, mid, sizeof(mid), r, tmp);
    if (tmp != NULL) {
        mqtt_retransmission_free(tmp);
    }
}

static void delete_retransmission(mqtt_session_t *mc, uint16_t mid)
{
    mqtt_retransmission_t *r;
    HASH_FIND(hh, mc->active_transmissions, &mid, sizeof(mid), r);
    if (r != NULL) {
        HASH_DEL(mc->active_transmissions, r);
        mqtt_retransmission_free(r);
    }
}

static void _mqtt_session_reconnect(int fd, short events, void *arg)
{
    (void) fd;
    (void) events;

    mqtt_session_t *mc = arg;

    mqtt_session_reconnect(mc);
}

static void call_error_cb(mqtt_session_t *mc, enum mqtt_session_error err, const char *errstr)
{
    if (mc->state == MQTT_STATE_CONNECTED) {
        mc->state = MQTT_STATE_ERROR;
        mqtt_session_disconnect(mc);
    } else {
        mc->state = MQTT_STATE_ERROR;
    }

    if ((mc->options & MQTT_SESSION_OPT_AUTORECONNECT) && (err != MQTT_ERROR_HARD && err != MQTT_ERROR_CONNECT)) {
        struct timeval tvl = { 1, 0 };
        event_base_once(mc->base, -1, EV_TIMEOUT, _mqtt_session_reconnect, mc, &tvl);
        return;
    }

    char *error = alloca(strlen(errstr) + 1);
    strcpy(error, errstr);

    if (mc->error_cb) {
        mc->error_cb(mc, err, error);
    }
}

static void call_debug_cb(mqtt_session_t *mc, const char *msg)
{
    if (mc->debug_cb) {
        mc->debug_cb(mc, msg);
    }
}

static void mqtt_send_connect(mqtt_session_t *mc)
{
    char *databuf;
    size_t datalen;

    if (!mqtt_write_connect_data(&mc->data, &databuf, &datalen)) {
        call_error_cb(mc, MQTT_ERROR_CONNECT, databuf);
        free(databuf);
        return;
    }

    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_CONNECT, 0, false, false };

    mqtt_write_header(&bufpnt, &hdr, datalen);
    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);
    bufferevent_write(mc->bev, databuf, datalen);

    free(databuf);

    call_debug_cb(mc, "sending connect");
}

static void mqtt_send_pingreq(mqtt_session_t *mc)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PINGREQ, 0, false, false };
    mqtt_write_header(&bufpnt, &hdr, 0);


    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);
    bufferevent_flush(mc->bev, EV_WRITE, BEV_FLUSH);

    call_debug_cb(mc, "sending pingreq");
}

static void mqtt_send_disconnect(mqtt_session_t *mc)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_DISCONNECT, 0, false, false };
    mqtt_write_header(&bufpnt, &hdr, 0);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    call_debug_cb(mc, "sending disconnect");
}

static void mqtt_send_subscribe(mqtt_session_t *mc, const char *topic, uint8_t qos, uint16_t mid)
{
    char *buf;
    size_t bufsize;

    if (!mqtt_write_string(topic, strlen(topic), &buf, &bufsize)) {
        call_error_cb(mc, MQTT_ERROR_PROTOCOL, buf);
        free(buf);
        return;
    }

    char *bufcpy = alloca(bufsize);
    memcpy(bufcpy, buf, bufsize);
    free(buf);

    uint16_t midbuf;
    void *midbufpnt = &midbuf;
    mqtt_write_uint16(&midbufpnt, mid);


    uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *hdrbufpnt = hdrbuf;

    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_SUBSCRIBE, 1, false, false };
    mqtt_write_header(&hdrbufpnt, &hdr, bufsize + sizeof(midbuf) + sizeof(qos));

    struct evbuffer *evb = evbuffer_new();

    evbuffer_add(evb, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
    evbuffer_add(evb, &midbuf, sizeof(midbuf));
    evbuffer_add(evb, bufcpy, bufsize);
    evbuffer_add(evb, &qos, sizeof(qos));

    add_retransmission(mc, evb, mid);

    bufferevent_write_buffer(mc->bev, evb);

    evbuffer_free(evb);

    call_debug_cb(mc, "sending subscribe");
}

static uint16_t mqtt_send_unsubscribe(mqtt_session_t *mc, const char *topic, uint16_t mid)
{
    uint16_t res = mc->next_mid;
    char *buf;
    size_t bufsize;

    if (!mqtt_write_string(topic, strlen(topic), &buf, &bufsize)) {
        call_error_cb(mc, MQTT_ERROR_PROTOCOL, buf);
        free(buf);
        return 0;
    }

    char *bufcpy = alloca(bufsize);
    memcpy(bufcpy, buf, bufsize);
    free(buf);

    uint16_t midbuf;
    void *midbufpnt = &midbuf;
    mqtt_write_uint16(&midbufpnt, mid);


    uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *hdrbufpnt = hdrbuf;

    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_UNSUBSCRIBE, 1, false, false };
    mqtt_write_header(&hdrbufpnt, &hdr, bufsize + sizeof(midbuf));

    struct evbuffer *evb = evbuffer_new();

    evbuffer_add(evb, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
    evbuffer_add(evb, &midbuf, sizeof(midbuf));
    evbuffer_add(evb, bufcpy, bufsize);

    bufferevent_write_buffer(mc->bev, evb);

    evbuffer_free(evb);

    add_retransmission(mc, evb, mid);

    call_debug_cb(mc, "sending unsubscribe");

    return res;
}

static void mqtt_send_publish(mqtt_session_t *mc, const char *topic, const void *data, size_t datalen, uint8_t qos, bool retain, uint16_t mid)
{
    char *topicbuf;
    size_t topicbufsize;

    if (!mqtt_write_string(topic, strlen(topic), &topicbuf, &topicbufsize)) {
        call_error_cb(mc, MQTT_ERROR_PROTOCOL, topicbuf);
        free(topicbuf);
        return;
    }

    uint16_t midbuf;
    void *midbufpnt = &midbuf;

    if (qos > 0) {
        mqtt_write_uint16(&midbufpnt, mid);
    }

    uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *hdrbufpnt = hdrbuf;
    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBLISH, qos, retain, false };
    mqtt_write_header(&hdrbufpnt, &hdr, topicbufsize + ((uintptr_t) midbufpnt - (uintptr_t) &midbuf) + datalen);

    struct evbuffer *evb = evbuffer_new();

    evbuffer_add(evb, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
    evbuffer_add(evb, topicbuf, topicbufsize);
    evbuffer_add(evb, &midbuf, ((uintptr_t) midbufpnt - (uintptr_t) &midbuf));
    evbuffer_add(evb, data, datalen);

    if (qos > 0) {
        add_retransmission(mc, evb, mid);
    }

    bufferevent_write_buffer(mc->bev, evb);

    evbuffer_free(evb);

    call_debug_cb(mc, "sending publish");

    evbuffer_free(evb);
}

static void mqtt_send_puback(mqtt_session_t *mc, uint16_t mid)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBACK, 1, false, false };
    mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
    mqtt_write_uint16(&bufpnt, mid);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    call_debug_cb(mc, "sending puback");
}

static void mqtt_send_pubrec(mqtt_session_t *mc, uint16_t mid)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBREC, 2, false, false };
    mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
    mqtt_write_uint16(&bufpnt, mid);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    call_debug_cb(mc, "sending pubrec");
}

static void mqtt_send_pubrel(mqtt_session_t *mc, uint16_t mid)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBREL, 2, false, false };
    mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
    mqtt_write_uint16(&bufpnt, mid);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    call_debug_cb(mc, "sending pubrel");
}

static void mqtt_send_pubcomp(mqtt_session_t *mc, uint16_t mid)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr = { MQTT_MESSAGE_TYPE_PUBCOMP, 2, false, false };
    mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
    mqtt_write_uint16(&bufpnt, mid);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    call_debug_cb(mc, "sending pubcomp");
}

static void handle_connack(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) len;

    mqtt_connack_data_t data;
    mqtt_read_connack_data(&buf, &data);

    if (data.return_code != MQTT_CONNACK_ACCEPTED) {
        call_error_cb(mc, MQTT_ERROR_CONNECT, mqtt_connack_code_str(data.return_code));
        mc->state = MQTT_STATE_ERROR;
        return;
    }

    mc->state = MQTT_STATE_CONNECTED;
    mc->awaiting_ping = false;

    struct timeval interval = { mc->data.keep_alive, 0 };
    event_add(mc->timeout_evt, &interval);

    if (mc->event_cb) {
        mc->event_cb(mc, MQTT_EVENT_CONNECTED);
    }

    mqtt_retransmission_t *r, *tmp;

    HASH_ITER(hh, mc->active_transmissions, r, tmp) {
        mqtt_retransmission_resume(r);
    }

    call_debug_cb(mc, "received connack");
}

static void handle_pingresp(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) buf;
    (void) len;

    mc->awaiting_ping = false;

    call_debug_cb(mc, "received pingresp");
}

static void handle_publish(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    char *topic;
    size_t topic_len;

    if (!mqtt_read_string(&buf, &len, &topic, &topic_len)) {
        call_error_cb(mc, MQTT_ERROR_PROTOCOL, topic);
        free(topic);
        return;
    }

    uint16_t mid;

    if (hdr->qos > 0) {
        mid = mqtt_read_uint16(&buf);
        len -= 2;
    }

    //TODO if (hdr->qos != 2)
    if (mc->msg_cb) {
        mc->msg_cb(mc, topic, buf, len, hdr->retain, hdr->qos, mc->msg_cb_arg);
    }

    free(topic);

    if (hdr->qos > 0) {
        mqtt_send_puback(mc, mid);
    }

    //mqtt_send_pubrec(mc, mid);

    call_debug_cb(mc, "received publish");
}

static void handle_puback(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) buf;

    uint16_t mid;

    mid = mqtt_read_uint16(&buf);
    len -= 2;

    delete_retransmission(mc, mid);
    delete_retransmission(mc, mid);

    call_debug_cb(mc, "received puback");
}

static void handle_suback(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) buf;

    uint16_t mid;

    mid = mqtt_read_uint16(&buf);
    len -= 2;

    delete_retransmission(mc, mid);

    call_debug_cb(mc, "received suback");
}

static void handle_unsuback(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) buf;
    (void) len;

    call_debug_cb(mc, "received unsuback");
}

static void mqtt_timeout(evutil_socket_t fd, short events, void *arg)
{
    (void) fd;
    (void) events;

    mqtt_session_t *mc = (mqtt_session_t *) arg;

    // TODO
    switch (mc->state) {
    case MQTT_STATE_CONNECTING:
        call_error_cb(mc, MQTT_ERROR_NETWORK, "timeout waiting for CONACK");
        break;

    case MQTT_STATE_CONNECTED:
        if (mc->awaiting_ping) {
            goto timeout;
        }

        mqtt_send_pingreq(mc);
        mc->awaiting_ping = true;
        break;

    case MQTT_STATE_DISCONNECTING:
        mqtt_session_disconnect(mc);
        break;

    default:
        event_del(mc->timeout_evt);
        call_error_cb(mc, MQTT_ERROR_UNKNOWN, "checking for timout in unknown state!");
    }

    return;

timeout:
    call_error_cb(mc, MQTT_ERROR_NETWORK, "timeout waiting for PINGRESP");
}

static void event_callback(struct bufferevent *bev, short what, void *ctx)
{
    (void) bev;

    mqtt_session_t *mc = (mqtt_session_t *) ctx;

    if (what & BEV_EVENT_CONNECTED) {

    }

    if (what & BEV_EVENT_EOF) {
        if ((mc->state == MQTT_STATE_DISCONNECTING) || (mc->state == MQTT_STATE_DISCONNECTED))
            return;

        char buf[1024];
        sprintf(buf, "socket closed");

        call_error_cb(mc, MQTT_ERROR_NETWORK, buf);
    }

    if (what & BEV_EVENT_ERROR) {
        char buf[1024];
        sprintf(buf, "bev-error(%d): %d", what, EVUTIL_SOCKET_ERROR());

        call_error_cb(mc, MQTT_ERROR_NETWORK, buf);
    }

    if (what & BEV_EVENT_TIMEOUT) {
        call_error_cb(mc, MQTT_ERROR_NETWORK, "bev-timeout");
    }
}

static void read_callback(struct bufferevent *bev, void *ctx)
{
    mqtt_session_t *mc = (mqtt_session_t *) ctx;
    struct evbuffer *inbuf = bufferevent_get_input(bev);

    mqtt_proto_header_t hdr;
    uint8_t buf[5];
    void *bufpnt;
    //look into the buffer
    size_t remaining_length;
    ssize_t headerlen = evbuffer_copyout(inbuf, buf, sizeof(buf));
    if (headerlen < 0) {
        bufferevent_setwatermark(bev, EV_READ, 2, 0);
        return;
    }

    bufpnt = buf;
    //OK, maybe my api-design sucks for this...
    mqtt_read_header(&bufpnt, &hdr);

    // check whether we can read the whole 'remaining length'-field
    bufpnt = buf + 1;

    if (!read_remaining_size(&bufpnt, &remaining_length, headerlen - 1)) {
        if (headerlen >= MQTT_MAX_FIXED_HEADER_SIZE) {
            // protocol allows a maximum of 4 bytes for that field
            call_error_cb(mc, MQTT_ERROR_PROTOCOL, "remaining length faulty");
            return;
        }

        // request one more byte than we were able to read
        bufferevent_setwatermark(bev, EV_READ, headerlen + 1, 0);
        return;
    }

    headerlen = ((uintptr_t) bufpnt - (uintptr_t) buf);

    size_t framelen = remaining_length + headerlen;
    ssize_t readlen;

    if (evbuffer_get_length(inbuf) < framelen) {
        bufferevent_setwatermark(bev, EV_READ, framelen, 0);
        return;
    }

    // about 4 MB
    if (framelen >= 0x400000) {
        call_debug_cb(mc, "got really big publish");
        evbuffer_drain(inbuf, framelen);
        return;
    }

    void *buffer = alloca(framelen);

    if ((readlen = evbuffer_copyout(inbuf, buffer, framelen)) == -1) {
        call_error_cb(mc, MQTT_ERROR_NETWORK, "evbuffer_copyout -1");
        return;
    }

    if ((size_t) readlen < framelen) {
        bufferevent_setwatermark(bev, EV_READ, framelen, 0);
        return;
    }

    // this actually removes data from the buffer
    evbuffer_drain(inbuf, readlen);

    bufpnt = (uint8_t *) buffer + headerlen;

    switch (hdr.msg_type) {
    case MQTT_MESSAGE_TYPE_CONNACK:
        handle_connack(mc, &hdr, bufpnt, remaining_length);
        break;

    case MQTT_MESSAGE_TYPE_PUBLISH:
        handle_publish(mc, &hdr, bufpnt, remaining_length);
        break;

    case MQTT_MESSAGE_TYPE_PINGRESP:
        handle_pingresp(mc, &hdr, bufpnt, remaining_length);
        break;

    case MQTT_MESSAGE_TYPE_PUBACK:
        handle_puback(mc, &hdr, bufpnt, remaining_length);
        break;

    case MQTT_MESSAGE_TYPE_SUBACK:
        handle_suback(mc, &hdr, bufpnt, remaining_length);
        break;

    case MQTT_MESSAGE_TYPE_UNSUBACK:
        handle_unsuback(mc, &hdr, bufpnt, remaining_length);
        break;

    case MQTT_MESSAGE_TYPE_PUBREC:

        //handle_pubrec(mc, &hdr, bufpnt, remaining_length);
    case MQTT_MESSAGE_TYPE_PUBREL:

        //handle_pubrel(mc, &hdr, bufpnt, remaining_length);
    case MQTT_MESSAGE_TYPE_PUBCOMP:

        //handle_pubcomp(mc, &hdr, bufpnt, remaining_length);

    case MQTT_MESSAGE_TYPE_PINGREQ:
    case MQTT_MESSAGE_TYPE_DISCONNECT:
    case MQTT_MESSAGE_TYPE_CONNECT:
    case MQTT_MESSAGE_TYPE_SUBSCRIBE:
    case MQTT_MESSAGE_TYPE_UNSUBSCRIBE:
        break;

    default:
        call_error_cb(mc, MQTT_ERROR_PROTOCOL, "unkonwn message type");
    }

    // we got a whole message - the next thing we want to read is a header
    bufferevent_setwatermark(bev, EV_READ, 2, 0);
    bufferevent_trigger(bev, EV_READ, BEV_OPT_DEFER_CALLBACKS);
}

void mqtt_session_will_set(mqtt_session_t *mc, const char *topic, const void *payload, size_t payloadlen, uint8_t qos, bool retain)
{
    if (mc->data.will_topic.buf) {
        free(mc->data.will_topic.buf);
    }

    mc->data.will_topic.buf = strdup(topic);
    mc->data.will_topic.len = strlen(topic);

    if (mc->data.will_message.buf) {
        free(mc->data.will_message.buf);
    }

    mc->data.will_message.buf = malloc(payloadlen);
    memcpy(mc->data.will_message.buf, payload, payloadlen);
    mc->data.will_message.len = payloadlen;

    mc->data.will_retain = retain;
    mc->data.will_qos = qos;
    mc->data.will_flag = true;
}

void mqtt_session_set_event_cb(mqtt_session_t *mc, mqtt_session_event_handler_t cb)
{
    mc->event_cb = cb;
}

void mqtt_session_set_msg_cb(mqtt_session_t *mc, mqtt_session_message_handler_t msg_handler, void *msg_arg)
{
    mc->msg_cb = msg_handler;
    mc->msg_cb_arg = msg_arg;
}

void mqtt_session_set_notification_cb(mqtt_session_t *mc, mqtt_session_notification_handler_t cb)
{
    mc->debug_cb = cb;
}

void *mqtt_session_userdata(mqtt_session_t *mc)
{
    return mc->userdata;
}

struct event_base *mqtt_session_get_base(mqtt_session_t *mc)
{
    return mc->base;
}

mqtt_session_t *mqtt_session_create(struct event_base* base, uint8_t options, mqtt_session_error_handler_t err_handler, void* userdata)
{
    mqtt_session_t *res = malloc(sizeof(mqtt_session_t));
    res->state = MQTT_STATE_PREPARING;
    res->base = base;
    res->options = options;
    res->error_cb = err_handler;
    res->userdata = userdata;
    res->timeout_evt = event_new(res->base, -1, EV_TIMEOUT | EV_PERSIST, mqtt_timeout, res);

    res->data.will_flag = false;

    res->data.username.buf = NULL;
    res->data.password.buf = NULL;
    res->data.id.buf = NULL;
    res->data.will_message.buf = NULL;
    res->data.will_topic.buf = NULL;

    res->data.proto_name.buf = strdup(MQTT_PROTOCOL_MAGIC);
    res->data.proto_name.len = strlen(MQTT_PROTOCOL_MAGIC);
    res->data.proto_version = MQTT_PROTOCOL_MAJOR;

    res->event_cb = NULL;
    res->debug_cb = NULL;
    res->msg_cb = NULL;

    res->bev = NULL;

    res->next_mid = 0;

    res->active_transmissions = NULL;

    return res;
}

void mqtt_session_setup(mqtt_session_t *mc, build_connection_t conn_builder, void *conn_state)
{
    mc->conn_builder = conn_builder;
    mc->conn_state = conn_state;
}

void mqtt_session_connect(mqtt_session_t *mc, char *id, bool clean_session, uint16_t keep_alive, char *username, char *password)
{
    if (mc->state != MQTT_STATE_PREPARING) {
        call_error_cb(mc, MQTT_ERROR_STATE, "calling connect is only allowed once");
        return;
    }

    mc->state = MQTT_STATE_CONNECTING;
    mc->awaiting_ping = false;

    mc->data.clean_session = clean_session;
    mc->data.keep_alive = keep_alive;

    if (mc->data.id.buf) {
        free(mc->data.id.buf);
    }

    if (id) {
        mc->data.id.len = strnlen(id, 23) + 1;
        mc->data.id.buf = malloc(mc->data.id.len);
        memcpy(mc->data.id.buf, id, mc->data.id.len);
        ((char *) mc->data.id.buf)[mc->data.id.len - 1] = '\0';
    }
    else {
        // TODO
        mc->data.id.buf = malloc(20);
        mc->data.id.len = snprintf(mc->data.id.buf, 20, "eyeyeyey%dlol", getpid());
    }

    if (username) {
        if (mc->data.username.buf) {
            free(mc->data.username.buf);
        }

        mc->data.username.buf = strdup(username);
        mc->data.username.len = strlen(username);
    }

    if (password) {
        if (mc->data.password.buf) {
            free(mc->data.password.buf);
        }

        mc->data.password.buf = strdup(password);
        mc->data.password.len = strlen(password);
    }

    mqtt_session_reconnect(mc);
}

void mqtt_session_reconnect(mqtt_session_t *mc)
{
    if (mc ->state == MQTT_STATE_CONNECTED) {
        mqtt_session_disconnect(mc);
    }

    mc->state = MQTT_STATE_CONNECTING;

    if (mc->bev)
        bufferevent_free(mc->bev);

    mc->bev = mc->conn_builder(mc->conn_state);

    if (!mc->bev) {
        call_error_cb(mc, MQTT_ERROR_HARD, "got a NULL bufferevent");
        mc->state = MQTT_STATE_DISCONNECTED;
        return;
    }

    bufferevent_setwatermark(mc->bev, EV_READ, 2, 0);
    bufferevent_setcb(mc->bev, read_callback, NULL, event_callback, mc);
    bufferevent_enable(mc->bev, EV_READ); /* Start reading. */

    mqtt_send_connect(mc);
    struct timeval interval = { mc->data.keep_alive, 0 };
    event_add(mc->timeout_evt, &interval);
}

void mqtt_session_disconnect(mqtt_session_t *mc)
{
    char buf[1024];

    switch (mc->state) {
    case MQTT_STATE_CONNECTED:
        mqtt_send_disconnect(mc);
        mc->state = MQTT_STATE_DISCONNECTING;
        struct timeval interval = { 1, 0 };
        event_add(mc->timeout_evt, &interval);
        return;

    case MQTT_STATE_DISCONNECTING:
    case MQTT_STATE_ERROR:
        break;

    default:
        sprintf(buf, "can't disconnect from this state: %d", mc->state);
        call_error_cb(mc, MQTT_ERROR_STATE, buf);
    }

    if (mc->bev) {
        bufferevent_free(mc->bev);
        mc->bev = NULL;
    }
    event_del(mc->timeout_evt);
    mc->state = MQTT_STATE_DISCONNECTED;

    if (mc->event_cb) {
        mc->event_cb(mc, MQTT_EVENT_DISCONNECTED);
    }
}

void mqtt_session_cleanup(mqtt_session_t *mc)
{
    {
        mqtt_retransmission_t *r, *tmp;

        HASH_ITER(hh, mc->active_transmissions, r, tmp) {
            HASH_DEL(mc->active_transmissions, r);
            mqtt_retransmission_free(r);
        }
    }

    if (mc->bev) {
        bufferevent_flush(mc->bev, EV_WRITE, BEV_FLUSH);
        bufferevent_free(mc->bev);
    }

    event_free(mc->timeout_evt);

    free(mc->data.username.buf);
    free(mc->data.password.buf);
    free(mc->data.id.buf);
    free(mc->data.will_topic.buf);
    free(mc->data.will_message.buf);

    free(mc->data.proto_name.buf);

    free(mc);
}

void mqtt_session_sub(mqtt_session_t *mc, const char *topic, int qos)
{
    if (mc->state == MQTT_STATE_CONNECTED)
        mqtt_send_subscribe(mc, topic, qos, mc->next_mid++);
}

void mqtt_session_unsub(mqtt_session_t *mc, const char *topic)
{
    if (mc->state == MQTT_STATE_CONNECTED)
        mqtt_send_unsubscribe(mc, topic, mc->next_mid++);
}

void mqtt_session_pub(mqtt_session_t *mc, const char *topic, const void *payload, size_t payloadlen, uint8_t qos, bool retain)
{
    if (mc->state == MQTT_STATE_CONNECTED) {
        uint16_t mid = 0;
        if (qos > 0)
            mid = mc->next_mid++;
        mqtt_send_publish(mc, topic, payload, payloadlen, qos, retain, mid);
    }
}
