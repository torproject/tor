/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rust_types.c
 * \brief This file is used for handling types returned from Rust to C.
 **/

#include "or.h"
#include "rust_types.h"

#ifdef HAVE_RUST

void free_rust_str(char *ret);

/* Because Rust strings can only be freed from Rust, we first copy the string's
 * contents to a c pointer, and then free the Rust string.
 * This function can be extended to return a success/error value if needed.
 */
void
move_rust_str_to_c_and_free(rust_str_ref_t src, char **dest)
{
  if (!src) {
    log_warn(LD_BUG, "Received a null pointer from protover rust.");
    return;
  }

  if (!dest) {
    log_warn(LD_BUG, "Received a null pointer from caller to protover rust. "
             "This results in a memory leak due to not freeing the rust "
             "string that was meant to be copied..");
    return;
  }

  *dest = tor_strdup(src);
  free_rust_str(src);
  return;
}

#else

/* When Rust is not enabled, this function should never be used. Log a warning
 * in the case that it is ever called when Rust is not enabled.
 */
void
move_rust_str_to_c_and_free(rust_str_ref_t src, char **dest)
{
  (void) src;
  (void) dest;
    log_warn(LD_BUG, "Received a call to free a Rust string when we are "
             " not running with Rust enabled.");
  return;
}
#endif /* defined(HAVE_RUST) */

