#ifndef __MQTT_H
#define __MQTT_H

#include <stdbool.h>

#include <event2/event.h>
#include <event2/bufferevent.h>

#include <event-magic/ssl.h>

struct mqtt_session;
typedef struct mqtt_session mqtt_session_t;

enum mqtt_session_error {
	MQTT_ERROR_PROTOCOL,
	MQTT_ERROR_NETWORK,
	MQTT_ERROR_CONNECT,
	MQTT_ERROR_STATE,
	MQTT_ERROR_HARD,
	MQTT_ERROR_UNKNOWN
};

enum mqtt_session_event {
	MQTT_EVENT_CONNECTED,
	MQTT_EVENT_DISCONNECTED
};


typedef void (*mqtt_session_event_handler_t)(mqtt_session_t *mc, enum mqtt_session_event evt);
void mqtt_session_set_event_cb(mqtt_session_t *mc, mqtt_session_event_handler_t cb);

/**
 * @param topic a UTF-8 encoded topic-name
 */
typedef void (*mqtt_session_message_handler_t)(mqtt_session_t *mc, const char *topic, const void *message, size_t len, bool retain, uint8_t qos, void *arg);
typedef void (*mqtt_session_error_handler_t)(mqtt_session_t *mc, enum mqtt_session_error err, char *msg);

#define MQTT_SESSION_OPT_AUTORECONNECT 1


mqtt_session_t *mqtt_session_create(struct event_base *base, uint8_t options, mqtt_session_error_handler_t err_handler, void *userdata);
void mqtt_session_cleanup(mqtt_session_t *mc);

/**
 * @param topic a UTF-8 encoded topic-name
 */
void mqtt_session_will_set(mqtt_session_t *mc, const char *topic, const void *payload, size_t payloadlen, uint8_t qos, bool retain);
void mqtt_session_set_msg_cb(mqtt_session_t *mc, mqtt_session_message_handler_t msg_handler, void *msg_arg);
void mqtt_session_set_clean_session(mqtt_session_t *mc, bool clean_session);

void mqtt_session_setup(mqtt_session_t *mc, build_connection_t conn_builder, void *conn_state);
void mqtt_session_connect(mqtt_session_t *mc, char *id, bool clean_session, uint16_t keep_alive, char *username, char *password);
void mqtt_session_reconnect(mqtt_session_t *mc);
void mqtt_session_disconnect(mqtt_session_t *mc);

void *mqtt_session_userdata(mqtt_session_t *mc);

/**
 * Publish a message.
 * @param topic a UTF-8 encoded topic-name
 * @return the message id used for sending. That is because currently logic for qos > 0 is not implemented.
 */
void mqtt_session_pub(mqtt_session_t *mc, const char *topic, const void *payload, size_t payloadlen, uint8_t qos, bool retain);

/**
 * @param topic a UTF-8 encoded topic-name
 */
void mqtt_session_sub(mqtt_session_t *mc, const char *topic, int qos);
/**
 * @param topic a UTF-8 encoded topic-name
 */
void mqtt_session_unsub(mqtt_session_t *mc, const char *topic);

typedef void (*mqtt_session_notification_handler_t)(mqtt_session_t *mc, const char *str);
void mqtt_session_set_notification_cb(mqtt_session_t *mc, mqtt_session_notification_handler_t cb);

struct event_base *mqtt_session_get_base(mqtt_session_t *mc);

#endif
