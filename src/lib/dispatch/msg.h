/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_DISPATCH_MSG_H
#define TOR_DISPATCH_MSG_H

#include "lib/cc/compat_compiler.h"
#include "lib/dispatch/msg_impl.h"

/** Flag for registering a message: declare that no other module is allowed to
 * publish this message if we are publishing it, or subscribe to it if we are
 * subscribing to it. */
#define DISP_FLAG_EXCL (1u<<0)

/** Flag for registering a message: declare that this message is a stub, and we
 * will not actually publish/subscribe it, but that the dispatcher should
 * treat us as if we did when typechecking.
 *
 * We use this so that messages aren't treated as "dangling" if they are
 * potentially used by some other build of Tor.
 */
#define DISP_FLAG_STUB (1u<<1)

/** Use this macro in a header to declare the existence of a given message.
 * It helps with strong typing.
 */
#define DECLARE_MESSAGE(messagename, typename, ctype)                   \
  typedef ctype msg_arg_type__ ##messagename;                           \
  typedef const ctype msg_arg_ctype__ ##messagename;                    \
  static const char msg_arg_name__ ##messagename[] = # typename;        \
  EAT_SEMICOLON

/**
 * Use this macro inside a C file to declare that we'll be publishing a given
 * message type from within this module. It helps with strong typing. */
#define DECLARE_PUBLISH(messagename)                                    \
  static pub_binding_t pub_binding__ ##messagename;                     \
  static void publish_fn__ ##messagename(msg_arg_type__ ##messagename arg) \
  {                                                                     \
    publish_internal(&pub_binding__ ##messagename, (void *) arg);       \
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
    arg = (msg_arg_type__ ## messagename) m->aux_data__;        \
    hookfn(m, arg);                                             \
  }                                                             \
  EAT_SEMICOLON

/**
 * This macro is for internal use.
 */
#define DISPATCH_ADD_PUB_(connector, channel, messagename, flags)       \
  dispatch_add_pub_((connector),                                        \
                    &pub_binding__ ##messagename,                       \
                    get_channel_id(# channel),                          \
                    get_message_id(# messagename),                      \
                    get_msg_type_id(msg_arg_name__ ## messagename),     \
                    (flags))

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
                    (flags));
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

#endif
