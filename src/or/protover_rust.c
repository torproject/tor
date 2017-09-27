/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * \file protover_rust.c
 * \brief Provide a C wrapper for functions exposed in /src/rust/protover,
 * and safe translation/handling between the Rust/C boundary.
 */

#include "or.h"
#include "protover.h"
#include "rust_types.h"

#ifdef HAVE_RUST

int rust_protover_all_supported(const char *s, char **missing);
rust_str_ref_t rust_protover_compute_for_old_tor(const char *version);
rust_str_ref_t rust_protover_compute_vote(const smartlist_t *proto_votes,
                                          int threshold);
rust_str_ref_t rust_protover_get_supported_protocols(void);
int rust_protocol_list_supports_protocol(const char *list, protocol_type_t tp,
                                         uint32_t version);
int rust_protover_is_supported_here(protocol_type_t pr, uint32_t ver);

/* Define for compatibility, used in main.c */
void protover_free_all(void) {};

/*
 * Wrap rust_protover_is_supported_here, located in /src/rust/protover
 */
int
protover_is_supported_here(protocol_type_t pr, uint32_t ver)
{
  return rust_protover_is_supported_here(pr, ver);
}

/*
 * Wrap rust_protover_list_supports_protocol, located  in /src/rust/protover
 */
int
protocol_list_supports_protocol(const char *list, protocol_type_t tp,
                                uint32_t version)
{
  return rust_protocol_list_supports_protocol(list, tp, version);
}

/*
 * Wrap rust_protover_get_supported_protocols, located in /src/rust/protover
 */
const char *
protover_get_supported_protocols(void)
{
  rust_str_ref_t rust_protocols = rust_protover_get_supported_protocols();

  char *protocols = NULL;
  if (rust_protocols != NULL) {
    move_rust_str_to_c_and_free(rust_protocols, &protocols);
  }
  return protocols;
}

/*
 * Wrap rust_protover_compute_vote, located in /src/rust/protover
 */
char *
protover_compute_vote(const smartlist_t *proto_strings,
                      int threshold)
{
  rust_str_ref_t rust_protocols = rust_protover_compute_vote(proto_strings,
                                                             threshold);

  char *protocols = NULL;
  if (rust_protocols != NULL) {
    move_rust_str_to_c_and_free(rust_protocols, &protocols);
  }
  return protocols;
}

/*
 * Wrap rust_protover_all_supported, located in /src/rust/protover
 */
int
protover_all_supported(const char *s, char **missing_out)
{
  rust_str_ref_t missing_out_copy = NULL;
  int is_supported  = rust_protover_all_supported(s, &missing_out_copy);

  if (!is_supported) {
    move_rust_str_to_c_and_free(missing_out_copy, missing_out);
  }

  return is_supported;
}

/*
 * Wrap rust_compute_for_old_tor, located in /src/rust/protover
 */
const char *
protover_compute_for_old_tor(const char *version)
{
  rust_str_ref_t rust_protocols = rust_protover_compute_for_old_tor(version);

  char *protocols = NULL;
  if (rust_protocols != NULL) {
    move_rust_str_to_c_and_free(rust_protocols, &protocols);
  }
  return protocols;
}

#endif

