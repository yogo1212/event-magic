#ifndef __MQTT_UTIL_H
#define __MQTT_UTIL_H

struct topic_tokenizer;
typedef struct topic_tokenizer topic_tokenizer_t;

topic_tokenizer_t *topic_tokenizer_create(const char *topic);
void topic_tokenizer_free(topic_tokenizer_t *tokenizer);

void topic_tokenizer_reset(topic_tokenizer_t *tokenizer);
/**
 * extracts the next particle from the topic.
 * @return the extracted particle or NULL if no particle could be read
 */
char *topic_tokenizer_get_next_particle(topic_tokenizer_t *from);

#endif
