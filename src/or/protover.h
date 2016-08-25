
#ifndef TOR_PROTOVER_H
#define TOR_PROTOVER_H

#include "container.h"

/* This is a guess. */
#define FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS "0.2.9.3-alpha"

typedef enum protocol_type_t {
  PRT_LINK,
  PRT_LINKAUTH,
  PRT_RELAY,
  PRT_HSMID,
  PRT_DIRCACHE,
  PRT_HSDIR,
  PRT_DESC,
  PRT_MICRODESC,
  PRT_CONS,
} protocol_type_t;

/*
const protover_set_t *protover_get_supported(void);
protover_set_t *protover_set_parse(const char *s);
int protover_is_supported_here_str(const char *name, uint32_t ver);
int protover_is_supported_by(protocol_type_t pr, uint32_t ver);
*/

int protover_all_supported(const char *s, char **missing);
int protover_is_supported_here(protocol_type_t pr, uint32_t ver);
const char *get_supported_protocols(void);

char * compute_protover_vote(const smartlist_t *list_of_proto_strings,
                             int threshold);
const char *protover_compute_for_old_tor(const char *version);


void protover_free_all(void);

#ifdef PROTOVER_PRIVATE
typedef struct proto_range_t {
  uint32_t low;
  uint32_t high;
} proto_range_t;

typedef struct proto_entry_t {
  char *name;
  smartlist_t *ranges;
} proto_entry_t;

STATIC smartlist_t *parse_protocol_list(const char *s);
STATIC void proto_entry_free(proto_entry_t *entry);
STATIC char *encode_protocol_list(const smartlist_t *sl);
STATIC const char *protocol_type_to_str(protocol_type_t pr);
STATIC int str_to_protocol_type(const char *s, protocol_type_t *pr_out);
#endif

#endif
