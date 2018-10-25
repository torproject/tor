/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_DISPATCH_MSG_H
#define TOR_DISPATCH_MSG_H

#include "lib/cc/compat_compiler.h"
#include "lib/dispatch/msg_impl.h"

#define DECLARE_MESSAGE_COMMON_(messagename, typename, ctype)           \
  typedef ctype msg_arg_type__ ##messagename;                           \
  typedef const ctype msg_arg_ctype__ ##messagename;                    \
  ATTR_UNUSED static const char msg_arg_name__ ##messagename[] = # typename;

/** Use this macro in a header to declare the existence of a given message,
 * taking a pointer as auxiliary data.
 *
 * It helps with strong typing.
 */
#define DECLARE_MESSAGE(messagename, typename, ctype)                   \
  DECLARE_MESSAGE_COMMON_(messagename, typename, ctype)                 \
  ATTR_UNUSED static inline ctype                                       \
  msg_arg_get__ ##messagename(msg_aux_data_t m)                         \
  {                                                                     \
    return m.ptr;                                                       \
  }                                                                     \
  ATTR_UNUSED static inline void                                        \
  msg_arg_set__ ##messagename(msg_aux_data_t *m, ctype v)               \
  {                                                                     \
    m->ptr = v;                                                         \
  }                                                                     \
  EAT_SEMICOLON

/** Use this macro in a header to declare the existence of a given message,
 * taking an integer as auxiliary data.
 *
 * It helps with strong typing.
 */
#define DECLARE_MESSAGE_INT(messagename, typename, ctype)               \
  DECLARE_MESSAGE_COMMON_(messagename, typename, ctype)                 \
  ATTR_UNUSED static inline ctype                                       \
  msg_arg_get__ ##messagename(msg_aux_data_t m)                         \
  {                                                                     \
    return (ctype)m.u64;                                                \
  }                                                                     \
  ATTR_UNUSED static inline void                                        \
  msg_arg_set__ ##messagename(msg_aux_data_t *m, ctype v)               \
  {                                                                     \
    m->u64 = (uint64_t)v;                                               \
  }                                                                     \
  EAT_SEMICOLON

/**
 * Use this macro inside a C file to declare that we'll be publishing a given
 * message type from within this module. It helps with strong typing. */
#define DECLARE_PUBLISH(messagename)                                    \
  static pub_binding_t pub_binding__ ##messagename;                     \
  static void                                                           \
  publish_fn__ ##messagename(msg_arg_type__ ##messagename arg)          \
  {                                                                     \
    msg_aux_data_t data;                                                \
    msg_arg_set__ ##messagename(&data, arg);                            \
    dispatch_pub_(&pub_binding__ ##messagename, data);                  \
  }                                                                     \
  EAT_SEMICOLON

/**
 * Use this macro inside a C file to declare that we're subscribing to a
 * given message and associating it with a given "hook function".  It
 * declares the hook function static, and helps with strong typing.
 */
#define DECLARE_SUBSCRIBE(messagename, hookfn) \
  static void hookfn(const msg_t *,                             \
                     const msg_arg_ctype__ ##messagename);      \
  static void recv_fn__ ## messagename(const msg_t *m)          \
  {                                                             \
    msg_arg_type__ ## messagename arg;                          \
    arg = msg_arg_get__ ##messagename(m->aux_data__);           \
    hookfn(m, arg);                                             \
  }                                                             \
  EAT_SEMICOLON

/**
 * This macro is for internal use.
 */
#define DISPATCH_ADD_PUB_(connector, channel, messagename, flags)       \
  (                                                                     \
    ((void)publish_fn__ ##messagename),                                 \
    dispatch_add_pub_((connector),                                      \
                      &pub_binding__ ##messagename,                     \
                      get_channel_id(# channel),                        \
                    get_message_id(# messagename),                      \
                      get_msg_type_id(msg_arg_name__ ## messagename),   \
                      (flags),                                          \
                      __FILE__,                                         \
                      __LINE__)                                         \
    )

/**
 * Use a given connector and channel name to declare that this subsystem will
 * publish a given message type.
 *
 * Call this macro from within the add_subscriptions() function of a module.
 */
#define DISPATCH_ADD_PUB(connector, channel, messagename)       \
    DISPATCH_ADD_PUB_(connector, channel, messagename, 0)

/**
 * Use a given connector and channel name to declare that this subsystem will
 * publish a given message type, and that no other subsystem is allowed to.
 *
 * Call this macro from within the add_subscriptions() function of a module.
 */
#define DISPATCH_ADD_PUB_EXCL(connector, channel, messagename)  \
    DISPATCH_ADD_PUB_(connector, channel, messagename, DISP_FLAG_EXCL)

/**
 * This macro is for internal use.
 */
#define DISPATCH_ADD_SUB_(connector, channel, messagename, flags)       \
  dispatch_add_sub_((connector),                                        \
                    recv_fn__ ##messagename,                            \
                    get_channel_id(#channel),                           \
                    get_message_id(# messagename),                      \
                    get_msg_type_id(msg_arg_name__ ##messagename),      \
                    (flags),                                            \
                    __FILE__,                                           \
                    __LINE__)
/*
 * Use a given connector and channel name to declare that this subsystem will
 * receive a given message type.
 *
 * Call this macro from within the add_subscriptions() function of a module.
 */
#define DISPATCH_ADD_SUB(connector, channel, messagename)       \
    DISPATCH_ADD_SUB_(connector, channel, messagename, 0)
/**
 * Use a given connector and channel name to declare that this subsystem will
 * receive a given message type, and that no other subsystem is allowed to do
 * so.
 *
 * Call this macro from within the add_subscriptions() function of a module.
 */
#define DISPATCH_ADD_SUB_EXCL(connector, channel, messagename)  \
    DISPATCH_ADD_SUB_(connector, channel, messagename, DISP_FLAG_EXCL)

/**
 * Publish a given message with a given argument.
 */
#define PUBLISH(messagename, arg)               \
  publish_fn__ ##messagename(arg)

/**
 * Use a given connector to declare that the functions to be used to manipuate
 * a certain C type.
 **/
#define DISPATCH_DEFINE_TYPE(con, type, fns)                    \
  dispatch_connector_define_type_((con),                        \
                                  get_msg_type_id(#type),       \
                                  (fns),                        \
                                  __FILE__,                     \
                                  __LINE__)

#endif
