#include <pcre.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "utarray.h"
#include "uthash.h"

#include "mqtt.h"

#include "mqtt_util.h"

struct mqtt_subscription;
typedef struct mqtt_subscription mqtt_subscription_t;

struct mqtt_subscription_engine {
    mqtt_session_t *mc;
    mqtt_subscription_t *subs;
};

struct mqtt_subscription_handler;
typedef struct mqtt_subscription_handler mqtt_subscription_handler_t;

struct mqtt_subscription_handler {
    mqtt_session_message_handler_t cb;
    void *ctx;
};

UT_icd mqtt_subscription_handler_icd = {sizeof(mqtt_subscription_handler_t), NULL, NULL, NULL};

struct mqtt_subscription {
    mqtt_subscription_engine_t *se;
    char *topic;
    uint8_t qos;

    pcre *topic_regex;
    pcre_extra *topic_regex_extra;

    UT_array *handlers;

    UT_hash_handle hh;
};

static char *dull_replace(const char *in, const char *pattern, const char *by)
{
    size_t outsize = strlen(in) + 1;
    // TODO maybe avoid reallocing by counting the non-overlapping occurences of pattern
    char *res = malloc(outsize);
    // use this to iterate over the output
    size_t resoffset = 0;

    char *needle;
    while ((needle = strstr(in, pattern))) {
        // copy everything up to the pattern
        memcpy(res + resoffset, in, needle - in);
        resoffset += needle - in;

        // skip the pattern in the input-string
        in = needle + strlen(pattern);

        // adjust space for replacement
        outsize = outsize - strlen(pattern) + strlen(by);
        res = realloc(res, outsize);

        // copy the pattern
        memcpy(res + resoffset, by, strlen(by));
        resoffset += strlen(by);
    }

    // copy the remaining input
    strcpy(res + resoffset, in);

    return res;
}

bool subscription_matches_topic(mqtt_subscription_t *sub, const char *topic)
{
    int pcreExecRet;
    int subStrVec[3 * 10];

    pcreExecRet = pcre_exec(sub->topic_regex,
                            sub->topic_regex_extra,
                            topic,
                            strlen(topic),  // length of string
                            0,              // Start looking at this point
                            0,              // OPTIONS
                            subStrVec,
                            sizeof(subStrVec)); // Length of subStrVec

    // Report what happened in the pcre_exec call..
    if (pcreExecRet < -1) { // Something dreadful happened..
        fprintf(stderr, "got pcreExecRet %d", pcreExecRet);
        return false;
    }
    else if (pcreExecRet == PCRE_ERROR_NOMATCH) {
        return false;
    }
    else {
        // we aren't using groups anyway, so we can ignore pcreExecRet == 0
        return true;
    }
}

static void mqtt_subscription_notify_handlers(mqtt_subscription_t *sub, mqtt_subscription_engine_t *se, const char *topic, const void *message, size_t len, bool retain, uint8_t qos)
{
    mqtt_subscription_handler_t *h;
    for(h = (mqtt_subscription_handler_t *) utarray_front(sub->handlers);
            h != NULL;
            h = (mqtt_subscription_handler_t *) utarray_next(sub->handlers, h)) {
        h->cb(se->mc, topic, message, len, retain, qos, h->ctx);
    }
}

static void mqtt_subscription_add_handler(mqtt_subscription_t *sub, mqtt_session_message_handler_t cb, void *ctx)
{
    mqtt_subscription_handler_t h = { cb, ctx };
    utarray_push_back(sub->handlers, &h);
}

static mqtt_subscription_handler_t *mqtt_subscription_find_handler(mqtt_subscription_t *sub, mqtt_session_message_handler_t cb, void *ctx)
{
    mqtt_subscription_handler_t *h;
    for(h = (mqtt_subscription_handler_t *) utarray_front(sub->handlers);
        h != NULL;
        h = (mqtt_subscription_handler_t *) utarray_next(sub->handlers, h)) {
        if (h->cb == cb && h->ctx == ctx) {
            return h;
        }
    }

     return NULL;
}

static bool mqtt_subscription_has_handlers(mqtt_subscription_t *sub)
{
    return utarray_len(sub->handlers) > 0;
}

static void mqtt_subscription_remove_handler(mqtt_subscription_t *sub, mqtt_session_message_handler_t cb, void *ctx)
{
    mqtt_subscription_handler_t *h;
    if (!(h = mqtt_subscription_find_handler(sub, cb, ctx)))
        return;

    mqtt_subscription_handler_t *back = utarray_back(sub->handlers);
    h->cb = back->cb;
    h->ctx = back->ctx;
    utarray_pop_back(sub->handlers);
}

static mqtt_subscription_t *mqtt_subscription_new(mqtt_subscription_engine_t *se, const char *topic, uint8_t qos)
{
    if (((topic == NULL) || (strlen(topic) == 0))) {
        return NULL;
    }

    char *regex = NULL, *tmp;
    tmp = dull_replace(topic, "+", "[^/\\x00]*");
    regex = dull_replace(tmp, "#", ".*");
    free(tmp);

    mqtt_subscription_t *res = malloc(sizeof(mqtt_subscription_t));

    res->topic = strdup(topic);
    res->qos = qos;
    res->se = se;

    const char *pcreErrorStr = NULL;
    int pcreErrorOffset = 0;

    // First, the regex string must be compiled.
    res->topic_regex = pcre_compile(regex, 0, &pcreErrorStr, &pcreErrorOffset, NULL);

    free(regex);

    // pcre_compile returns NULL on error, and sets pcreErrorOffset & pcreErrorStr
    if (res->topic_regex == NULL) {
        fprintf(stderr, "regex: Could not compile '%s': %s (%d)", regex, pcreErrorStr, pcreErrorOffset);
        goto error;
    }

    // Optimize the regex
    res->topic_regex_extra = pcre_study(res->topic_regex, 0, &pcreErrorStr);

    /*
     * pcre_study() returns NULL for both errors and when it can not optimize the regex.
     * The last argument is how one checks for errors
     * it is NULL if everything works, and points to an error string otherwise.
     */
    if (pcreErrorStr != NULL) {
        fprintf(stderr, "regex: Could not study '%s': %s", regex, pcreErrorStr);
    }

    mqtt_session_sub(res->se->mc, res->topic, res->qos);

    utarray_new(res->handlers, &mqtt_subscription_handler_icd);

    return res;

error:
    free(res->topic);

    free(res);

    return NULL;
}


static void mqtt_subscription_free(mqtt_subscription_t *sub)
{
    mqtt_session_unsub(sub->se->mc, sub->topic);

    utarray_free(sub->handlers);

    // free the EXTRA PCRE value (may be NULL at this point)
    if (sub->topic_regex_extra != NULL) {
        pcre_free(sub->topic_regex_extra);
    }

    // free the regular expression.
    pcre_free(sub->topic_regex);

    free(sub->topic);
    free(sub);
}

static void _mqtt_subscription_engine_msg_handler(mqtt_session_t *mc, const char *topic, const void *message, size_t len, bool retain, uint8_t qos, void *arg)
{
    (void) mc;

    mqtt_subscription_engine_t *se = arg;

    mqtt_subscription_t *sub, *tmp;
    HASH_ITER(hh, se->subs, sub, tmp) {
        if (subscription_matches_topic(sub, topic)) {
            mqtt_subscription_notify_handlers(sub, se, topic, message, len, retain, qos);
        }
    }
}

mqtt_subscription_engine_t *mqtt_subscription_engine_new(mqtt_session_t *mc)
{
    mqtt_subscription_engine_t *res = malloc(sizeof(mqtt_subscription_engine_t));
    res->mc = mc;
    res->subs = NULL;

    mqtt_session_set_msg_cb(mc, _mqtt_subscription_engine_msg_handler, res);

    return res;
}

bool mqtt_subscription_engine_sub(mqtt_subscription_engine_t *se, const char *topic, uint8_t qos, mqtt_session_message_handler_t cb, void *ctx)
{
    mqtt_subscription_t *sub;
    HASH_FIND_STR(se->subs, topic, sub);

    if (!sub) {
        sub = mqtt_subscription_new(se, topic, qos);
        if (!sub)
            return false;
        HASH_ADD_STR(se->subs, topic, sub);
   }

    mqtt_subscription_add_handler(sub, cb, ctx);

    return true;
}

void mqtt_subscription_engine_unsub(mqtt_subscription_engine_t *se, const char *topic, mqtt_session_message_handler_t cb, void *ctx)
{
    mqtt_subscription_t *sub;
    HASH_FIND_STR(se->subs, topic, sub);

    if (sub) {
        mqtt_subscription_remove_handler(sub, cb, ctx);
        if (mqtt_subscription_has_handlers(sub)) {
            HASH_DEL(se->subs, sub);
            mqtt_subscription_free(sub);
        }
    }
}

void mqtt_subscription_engine_resub(mqtt_subscription_engine_t *se)
{
    mqtt_subscription_t *sub, *tmp;
    HASH_ITER(hh, se->subs, sub, tmp) {
        mqtt_session_sub(se->mc, sub->topic, sub->qos);
    }
}

void mqtt_subscription_engine_free(mqtt_subscription_engine_t *se)
{
    mqtt_session_set_msg_cb(se->mc, NULL, NULL);

    mqtt_subscription_t *sub, *tmp;
    HASH_ITER(hh, se->subs, sub, tmp) {
        HASH_DEL(se->subs, sub);
        mqtt_subscription_free(sub);
    }

    free(se);
}


/*
 * The topic-tokenizer can be used to traverse a topic
 */

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
