#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/buffer.h>

#include "mqtt_proto.h"

#include "mqtt.h"

enum MQTT_STATE {
    //MQTT_STATE_INVALID = 0,
    MQTT_STATE_PREPARING,
    MQTT_STATE_CONNECTING,
    MQTT_STATE_CONNECTED,
    MQTT_STATE_DISCONNECTING,
    MQTT_STATE_DISCONNECTED,
    MQTT_STATE_TIMEOUT,
    MQTT_STATE_ERROR
};

struct mqtt_session {
    struct event_base *base;
    struct bufferevent *bev;
    build_connection_t conn_builder;
    void *conn_state;
    mqtt_session_message_handler_t msg_handler;
    mqtt_session_error_handler_t err_handler;
    char *last_error;
    void *userdata;
    bool awaiting_ping;
    struct event *timeout_evt;
    enum MQTT_STATE state;
    uint16_t next_mid;
    mqtt_connect_data_t data;
    mqtt_session_notification_handler_t notification_cb;
    mqtt_session_event_handler_t event_cb;
};

static void call_error(mqtt_session_t *mc, enum mqtt_session_error err, const char *errstr)
{
    if (mc->last_error) {
        free(mc->last_error);
    }

    mc->last_error = strdup(errstr);

    if (mc->err_handler) {
        mc->err_handler(mc, err);
    }

    if (mc->last_error) {
        free(mc->last_error);
        mc->last_error = NULL;
    }
}

char *mqtt_session_last_error(mqtt_session_t *mc)
{
    return mc->last_error;
}

/* TODO does this really belong to the session? */
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
        sprintf(buf, "socket-closed");

        if (mc->state == MQTT_STATE_CONNECTED) {
            mc->state = MQTT_STATE_ERROR;
        }

        call_error(mc, MQTT_ERROR_NETWORK, buf);
        mqtt_session_disconnect(mc);
    }

    if (what & BEV_EVENT_ERROR) {
        char buf[1024];
        sprintf(buf, "bev-error(%d): %d", what, EVUTIL_SOCKET_ERROR());

        if (mc->state == MQTT_STATE_CONNECTED) {
            mc->state = MQTT_STATE_ERROR;
        }

        call_error(mc, MQTT_ERROR_NETWORK, buf);
        mqtt_session_disconnect(mc);
    }

    if (what & BEV_EVENT_TIMEOUT) {
        if (mc->state == MQTT_STATE_CONNECTED) {
            mc->state = MQTT_STATE_TIMEOUT;
        }

        call_error(mc, MQTT_ERROR_NETWORK, "bev-timeout");
        mqtt_session_disconnect(mc);
    }
}

static void mqtt_send_connect(mqtt_session_t *mc)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr;
    hdr.dup = false;
    hdr.qos = 0;

    hdr.retain = false;
    hdr.msg_type = MQTT_MESSAGE_TYPE_CONNECT;

    char *databuf;
    size_t datalen;

    if (!mqtt_write_connect_data(&mc->data, &databuf, &datalen)) {
        call_error(mc, MQTT_ERROR_CONNECT, databuf);
        free(databuf);
        return;
    }

    mqtt_write_header(&bufpnt, &hdr, datalen);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    bufferevent_write(mc->bev, databuf, datalen);

    free(databuf);

    if (mc->notification_cb) {
        mc->notification_cb(mc, "sending connect");
    }
}

static void mqtt_send_pingreq(mqtt_session_t *mc)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr;

    hdr.dup = false;
    hdr.qos = 0;
    hdr.retain = false;
    hdr.msg_type = MQTT_MESSAGE_TYPE_PINGREQ;
    mqtt_write_header(&bufpnt, &hdr, 0);


    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);
    // sadly, libevent might not automatically think it's necessary to send this NOW`
    bufferevent_flush(mc->bev, EV_WRITE, BEV_FLUSH);

    if (mc->notification_cb) {
        mc->notification_cb(mc, "sending pingreq");
    }
}

static void mqtt_send_disconnect(mqtt_session_t *mc)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr;

    hdr.dup = false;
    hdr.qos = 0;
    hdr.retain = false;
    hdr.msg_type = MQTT_MESSAGE_TYPE_DISCONNECT;
    mqtt_write_header(&bufpnt, &hdr, 0);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    if (mc->notification_cb) {
        mc->notification_cb(mc, "sending disconnect");
    }
}

static uint16_t mqtt_send_subscribe(mqtt_session_t *mc, char *topic, uint8_t qos)
{
    uint16_t res = mc->next_mid;
    char *buf;
    size_t bufsize;

    if (!mqtt_write_string(topic, strlen(topic), &buf, &bufsize)) {
        call_error(mc, MQTT_ERROR_PROTOCOL, buf);
        free(buf);
        return 0;
    }

    char *bufcpy = alloca(bufsize);
    memcpy(bufcpy, buf, bufsize);
    free(buf);

    uint16_t midbuf;
    void *midbufpnt = &midbuf;
    mqtt_write_uint16(&midbufpnt, ++(mc->next_mid));


    uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *hdrbufpnt = hdrbuf;

    mqtt_proto_header_t hdr;

    hdr.dup = false;
    hdr.qos = 1;
    hdr.retain = false;
    hdr.msg_type = MQTT_MESSAGE_TYPE_SUBSCRIBE;
    mqtt_write_header(&hdrbufpnt, &hdr, bufsize + sizeof(midbuf) + sizeof(qos));

    bufferevent_write(mc->bev, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
    bufferevent_write(mc->bev, &midbuf, sizeof(midbuf));
    bufferevent_write(mc->bev, bufcpy, bufsize);
    bufferevent_write(mc->bev, &qos, sizeof(qos));

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "sending subscribe");
    }

    return res;
}

static uint16_t mqtt_send_unsubscribe(mqtt_session_t *mc, char *topic)
{
    uint16_t res = mc->next_mid;
    char *buf;
    size_t bufsize;

    if (!mqtt_write_string(topic, strlen(topic), &buf, &bufsize)) {
        call_error(mc, MQTT_ERROR_PROTOCOL, buf);
        free(buf);
        return 0;
    }

    char *bufcpy = alloca(bufsize);
    memcpy(bufcpy, buf, bufsize);
    free(buf);

    uint16_t midbuf;
    void *midbufpnt = &midbuf;
    mqtt_write_uint16(&midbufpnt, ++(mc->next_mid));


    uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *hdrbufpnt = hdrbuf;

    mqtt_proto_header_t hdr;

    hdr.dup = false;
    hdr.qos = 1;
    hdr.retain = false;
    hdr.msg_type = MQTT_MESSAGE_TYPE_SUBSCRIBE;
    mqtt_write_header(&hdrbufpnt, &hdr, bufsize + sizeof(midbuf));

    bufferevent_write(mc->bev, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
    bufferevent_write(mc->bev, &midbuf, sizeof(midbuf));
    bufferevent_write(mc->bev, bufcpy, bufsize);

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "sending unsubscribe");
    }

    return res;
}

static uint16_t mqtt_send_publish(mqtt_session_t *mc, char *topic, const void *data, size_t datalen, uint8_t qos, bool retain)
{
    uint16_t res = mc->next_mid;
    char *topicbuf;
    size_t topicbufsize;

    if (!mqtt_write_string(topic, strlen(topic), &topicbuf, &topicbufsize)) {
        call_error(mc, MQTT_ERROR_PROTOCOL, topicbuf);
        free(topicbuf);
        return 0;
    }

    uint16_t midbuf;
    void *midbufpnt = &midbuf;

    if (qos > 0) {
        mqtt_write_uint16(&midbufpnt, ++(mc->next_mid));
    }

    uint8_t hdrbuf[MQTT_MAX_FIXED_HEADER_SIZE];
    void *hdrbufpnt = hdrbuf;

    mqtt_proto_header_t hdr;

    hdr.dup = false;
    hdr.qos = qos;
    hdr.retain = retain;
    hdr.msg_type = MQTT_MESSAGE_TYPE_PUBLISH;
    mqtt_write_header(&hdrbufpnt, &hdr, topicbufsize + ((uintptr_t) midbufpnt - (uintptr_t) &midbuf) + datalen);

    bufferevent_write(mc->bev, hdrbuf, (uintptr_t) hdrbufpnt - (uintptr_t) hdrbuf);
    bufferevent_write(mc->bev, topicbuf, topicbufsize);
    bufferevent_write(mc->bev, &midbuf, ((uintptr_t) midbufpnt - (uintptr_t) &midbuf));
    bufferevent_write(mc->bev, data, datalen);

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "sending publish");
    }

    return res;
}

static void mqtt_send_puback(mqtt_session_t *mc, uint16_t mid)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr;
    // TODO
    hdr.dup = false;

    hdr.qos = 1;
    hdr.retain = false;
    hdr.msg_type = MQTT_MESSAGE_TYPE_PUBACK;
    mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
    mqtt_write_uint16(&bufpnt, mid);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "sending puback");
    }
}

static void mqtt_send_pubrec(mqtt_session_t *mc, uint16_t mid)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr;
    // TODO
    hdr.dup = false;

    hdr.qos = 1;
    hdr.retain = false;
    hdr.msg_type = MQTT_MESSAGE_TYPE_PUBREC;
    mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
    mqtt_write_uint16(&bufpnt, mid);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "sending pubrec");
    }
}

static void mqtt_send_pubrel(mqtt_session_t *mc, uint16_t mid)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr;
    // TODO
    hdr.dup = false;

    hdr.qos = 1;
    hdr.retain = false;
    hdr.msg_type = MQTT_MESSAGE_TYPE_PUBREL;
    mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
    mqtt_write_uint16(&bufpnt, mid);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "sending pubrel");
    }
}

static void mqtt_send_pubcomp(mqtt_session_t *mc, uint16_t mid)
{
    uint8_t buf[MQTT_MAX_FIXED_HEADER_SIZE + 2];
    void *bufpnt = buf;

    mqtt_proto_header_t hdr;
    // TODO
    hdr.dup = false;

    hdr.qos = 1;
    hdr.retain = false;
    hdr.msg_type = MQTT_MESSAGE_TYPE_PUBCOMP;
    mqtt_write_header(&bufpnt, &hdr, sizeof(uint16_t));
    mqtt_write_uint16(&bufpnt, mid);

    bufferevent_write(mc->bev, buf, (uintptr_t) bufpnt - (uintptr_t) buf);

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "sending pubcomp");
    }
}

static void handle_publish(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    char *topic;
    size_t topic_len;

    if (!mqtt_read_string(&buf, &len, &topic, &topic_len)) {
        call_error(mc, MQTT_ERROR_PROTOCOL, topic);
        free(topic);
        return;
    }

    uint16_t mid;

    if (hdr->qos > 0) {
        mid = mqtt_read_uint16(&buf);
        len -= 2;
    }

    //TODO if (hdr->qos != 2)
    if (mc->msg_handler) {
        mc->msg_handler(mc, topic, buf, len);
    }

    free(topic);

    if (hdr->qos > 0) {
        mqtt_send_puback(mc, mid);
    }

    //mqtt_send_pubrec(mc, mid);
    // qos = 2 pubrec

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "received publish");
    }
}

static void handle_connack(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) len;

    mqtt_connack_data_t data;
    mqtt_read_connack_data(&buf, &data);

    if (data.return_code != MQTT_CONNACK_ACCEPTED) {
        call_error(mc, MQTT_ERROR_CONNECT, mqtt_connack_code_str(data.return_code));
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

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "received connack");
    }
}

static void handle_pingresp(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) buf;
    (void) len;

    mc->awaiting_ping = false;

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "received pingresp");
    }
}

static void handle_puback(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) buf;
    (void) len;

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "received puback");
    }
}

static void handle_suback(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) buf;
    (void) len;

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "received suback");
    }
}

static void handle_unsuback(mqtt_session_t *mc, mqtt_proto_header_t *hdr, void *buf, size_t len)
{
    (void) hdr;
    (void) buf;
    (void) len;

    if (mc->notification_cb) {
        // TODO more elaborate
        mc->notification_cb(mc, "received unsuback");
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

    bufpnt = buf;
    //OK, maybe my api-design sucks for this...
    mqtt_read_header(&bufpnt, &hdr);

    // check whether we can read the whole 'remaining length'-field
    bufpnt = buf + 1;

    if (!read_remaining_size(&bufpnt, &remaining_length, headerlen - 1)) {
        if (headerlen >= MQTT_MAX_FIXED_HEADER_SIZE) {
            // protocol allows a maximum of 4 bytes for that field
            call_error(mc, MQTT_ERROR_PROTOCOL, "remaining length faulty");
            return;
        }

        // request one more byte than we were able to read
        bufferevent_setwatermark(bev, EV_READ, headerlen + 1, 0);
        return;
    }

    headerlen = ((uintptr_t) bufpnt - (uintptr_t) buf);

    ssize_t framelen = remaining_length + headerlen, readlen;
    void *buffer = alloca(framelen);

    if ((readlen = evbuffer_copyout(inbuf, buffer, framelen)) < framelen) {
        if (readlen == -1) {
            call_error(mc, MQTT_ERROR_NETWORK, "evbuffer_copyout -1");
            return;
        }

        bufferevent_setwatermark(bev, EV_READ, headerlen + remaining_length, 0);
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
            call_error(mc, MQTT_ERROR_PROTOCOL, "unkonwn message type");
    }

    // we got a whole message - the next thing we want to read is a header
    bufferevent_setwatermark(bev, EV_READ, 2, 0);
    bufferevent_trigger(bev, EV_READ, BEV_OPT_DEFER_CALLBACKS);
}

static void mqtt_timeout(evutil_socket_t fd, short events, void *arg)
{
    (void) fd;
    (void) events;

    mqtt_session_t *mc = (mqtt_session_t *) arg;

    // TODO
    switch (mc->state) {
        case MQTT_STATE_CONNECTING:
            call_error(mc, MQTT_ERROR_NETWORK, "timeout waiting for CONACK");
            break;

        case MQTT_STATE_CONNECTED:
            if (mc->awaiting_ping) {// 1.5
                call_error(mc, MQTT_ERROR_NETWORK, "timeout waiting for PINGRESP");
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
            call_error(mc, MQTT_ERROR_UNKNOWN, "checking for timout in unkown state!");
    }

    return;

timeout:
    mc->state = MQTT_STATE_TIMEOUT;
    mqtt_session_disconnect(mc);
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

void mqtt_session_set_notification_cb(mqtt_session_t *mc, mqtt_session_notification_handler_t cb)
{
    mc->notification_cb = cb;
}

void mqtt_session_disconnect(mqtt_session_t *mc)
{
    char buf[1024];

    switch (mc->state) {
        case MQTT_STATE_CONNECTED:
            mqtt_send_disconnect(mc);
            mc->state = MQTT_STATE_DISCONNECTING;

            // somebody might have started the client, sent a message and then killed it. try to deliver that message.
            if (evbuffer_get_length(bufferevent_get_output(mc->bev)) > 0) {
                struct timeval timeout = { 2, 0 };
                event_add(mc->timeout_evt, &timeout);
                break;
            }

        case MQTT_STATE_DISCONNECTING:
        case MQTT_STATE_ERROR:
        case MQTT_STATE_TIMEOUT:
            goto just_do_it;
            break;

        default:
            sprintf(buf, "can't disconnect from this state: %d", mc->state);
            call_error(mc, MQTT_ERROR_STATE, buf);
    }

    return;

just_do_it:
    // TODO close transport
    event_del(mc->timeout_evt);
    mc->state = MQTT_STATE_DISCONNECTED;

    if (mc->event_cb) {
        mc->event_cb(mc, MQTT_EVENT_DISCONNECTED);
    }
}

void mqtt_session_connect(mqtt_session_t *mc, char *id, bool clean_session, uint16_t keep_alive, char *username, char *password)
{
    if (mc->state != MQTT_STATE_PREPARING) {
        call_error(mc, MQTT_ERROR_STATE, "calling connect is only allowed once");
        return;
    }

    mc->notification_cb = NULL;

    mc->state = MQTT_STATE_CONNECTING;
    mc->awaiting_ping = false;

    mc->data.clean_session = clean_session;
    mc->data.keep_alive = keep_alive;

    if (mc->data.id.buf) {
        free(mc->data.id.buf);
    }

    if (id) {
        mc->data.id.buf = strdup(id);
        mc->data.id.len = strlen(id);
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
}

void mqtt_session_reconnect(mqtt_session_t* mc, bool clean_session)
{
    // TODO only valid if disconnected or connected
    mc->data.clean_session = clean_session;

    if (mc->bev)
        bufferevent_free(mc->bev);

    mc->bev = mc->conn_builder(mc->conn_state);

    bufferevent_setwatermark(mc->bev, EV_READ, 2, 0);
    bufferevent_setcb(mc->bev, read_callback, NULL, event_callback, mc);
    bufferevent_enable(mc->bev, EV_READ); /* Start reading. */

    mqtt_send_connect(mc);
    struct timeval interval = { mc->data.keep_alive, 0 };
    event_add(mc->timeout_evt, &interval);
}

mqtt_session_t *mqtt_session_setup(struct event_base *base, build_connection_t conn_builder, void *conn_state, mqtt_session_message_handler_t msg_handler, mqtt_session_error_handler_t err_handler, void *userdata)
{
    mqtt_session_t *res = malloc(sizeof(mqtt_session_t));
    res->conn_builder = conn_builder;
    res->conn_state = conn_state;
    res->state = MQTT_STATE_PREPARING;
    res->base = base;
    res->bev = NULL;
    res->err_handler = err_handler;
    res->msg_handler = msg_handler;
    res->userdata = userdata;
    res->timeout_evt = event_new(res->base, -1, EV_TIMEOUT | EV_PERSIST, mqtt_timeout, res);
    res->last_error = NULL;

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

    res->next_mid = 0;

    return res;
}

void mqtt_session_cleanup(mqtt_session_t *mc)
{
    event_free(mc->timeout_evt);

    free(mc->data.username.buf);
    free(mc->data.password.buf);
    free(mc->data.id.buf);
    free(mc->data.will_topic.buf);
    free(mc->data.will_message.buf);

    free(mc->data.proto_name.buf);

    free(mc);
}

void mqtt_session_sub(mqtt_session_t *mc, char *topic, int qos)
{
    mqtt_send_subscribe(mc, topic, qos);
}

void mqtt_session_unsub(mqtt_session_t *mc, char *topic)
{
    mqtt_send_unsubscribe(mc, topic);
}

uint16_t mqtt_session_pub(mqtt_session_t *mc, char *topic, const void *payload, size_t payloadlen, uint8_t qos, bool retain)
{
    return mqtt_send_publish(mc, topic, payload, payloadlen, qos, retain);
}
