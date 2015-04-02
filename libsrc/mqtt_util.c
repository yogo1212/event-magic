#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mqtt_util.h"

/*
 * The maximum topic-length is implicitly and explicitly limited to HIGH(uint16_t).
 * There is no restriction for particles.
 */
#define MQTT_MAX_TOPIC_SIZE 0xFFFF
#define MQTT_MAX_PARTICLE_SIZE 0xFFFF

struct topic_tokenizer {
    char *topic_pnt;
    /* need space for zero-termination */
    char topic[MQTT_MAX_TOPIC_SIZE + 1];

    char current[MQTT_MAX_PARTICLE_SIZE + 1];
};

topic_tokenizer_t *topic_tokenizer_create(const char *topic)
{
    topic_tokenizer_t *res = malloc(sizeof(topic_tokenizer_t));

    strncpy(res->topic, topic, sizeof(res->topic) - 1);
    res->topic[sizeof(res->topic) - 1] = '\0';
    res->topic_pnt = res->topic;
    
    res->current[0] = '\0';

    return res;
}

void topic_tokenizer_free(topic_tokenizer_t *tokenizer)
{
    free(tokenizer);
}

void topic_tokenizer_reset(topic_tokenizer_t *tokenizer)
{
    tokenizer->topic_pnt = tokenizer->topic;
    tokenizer->current[0] = '\0';
}

char *topic_tokenizer_get_next_particle(topic_tokenizer_t *from)
{
    if (*from->topic_pnt == '\0') {
        return NULL;
    }

    char *dpos = strstr(from->topic_pnt, "/");

    if (dpos) {
        uintptr_t cnt = dpos - from->topic_pnt;
        memcpy(from->current, from->topic_pnt, cnt);
        from->current[cnt] = '\0';
        from->topic_pnt += cnt + 1;
    }
    else {
        strcpy(from->current, from->topic_pnt);
        from->topic_pnt = &from->topic[sizeof(from->topic) - 1];
    }

    return from->current;
}