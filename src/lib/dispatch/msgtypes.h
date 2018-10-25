/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_DISPATCH_MSGTYPES_H
#define TOR_DISPATCH_MSGTYPES_H

#include <stdint.h>
#include <stddef.h>

/**
 * These types are aliases for different items described above.
 **/
typedef uint16_t subsys_id_t;
typedef uint16_t channel_id_t;
typedef uint16_t message_id_t;

/**
 * This identifies a C type that can be sent along with a message.
 **/
typedef uint16_t msg_type_id_t;

#define ERROR_ID 65535

/**
 * Structure of a received message.
 */
typedef struct msg_t {
  subsys_id_t sender;
  channel_id_t channel;
  message_id_t msg;
  /** We could omit this field, since it is implicit in the message, but
   * IMO let's leave it in for safety. */
  msg_type_id_t type;
  /** Untyped auxiliary data. You shouldn't have to mess with this
   * directly. */
  void *aux_data__;
} msg_t;

typedef struct pub_binding_t {
  subsys_id_t sender;
  channel_id_t channel;
  message_id_t msg;
  msg_type_id_t type;
} pub_binding_t;

/**
 * A "dispatch connector" is a view of the dispatcher that a subsystem
 * uses while initializing itself.  It is specific to the subsystem, and
 * ensures that each subsystem doesn't need to identify itself
 * repeatedly while registering its messages.
 **/
typedef struct dispatch_connector_t dispatch_connector_t;

#endif
