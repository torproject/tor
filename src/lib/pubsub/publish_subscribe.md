
@page publish_subscribe Publish-subscribe message passing in Tor

@tableofcontents

## Introduction

Tor has introduced a generic publish-subscribe mechanism for delivering
messages internally.  It is meant to help us improve the modularity of
our code, by avoiding direct coupling between modules that don't
actually need to invoke one another.

This publish-subscribe mechanism is *not* meant for handing
multithreading or multiprocess issues, thought we hope that eventually
it might be extended and adapted for that purpose.  Instead, we use
publish-subscribe today to decouple modules that shouldn't be calling
each other directly.

For example, there are numerous parts of our code that might need to
take action when a circuit is completed: a controller might need to be
informed, an onion service negotiation might need to be attached, a
guard might need to be marked as working, or a client connection might
need to be attached.  But many of those actions occur at a higher layer
than circuit completion: calling them directly is a layering violation,
and makes our code harder to understand and analyze.

But with message-passing, we can invert this layering violation: circuit
completion can become a "message" that the circuit code publishes, and
to which higher-level layers subscribe.  This means that circuit
handling can be decoupled from higher-level modules, and stay nice and
simple. (@ref pubsub_notyet "1")

> @anchor pubsub_notyet 1. Unfortunately, like most of our code, circuit
> handling is _not_ yet refactored to use publish-subscribe throughout.
> Instead, layer violations of the type described here are pretty common
> in Tor today.  To see a small part of what happens when a circuit is
> completed today, have a look at circuit_build_no_more_hops() and its
> associated code.

## Channels and delivery policies

To work with messages, especially when refactoring existing code, you'll
need to understand "channels" and "delivery policies".

Every message is delivered on a "message channel".  Each channel
(conceptually) a queue-like structure that can support an arbitrarily
number of message types.  Where channels vary is their delivery
mechanisms, and their guarantees about when messages are processed.

Currently, three delivery policies are possible:

   - `DELIV_PROMPT` -- causes messages to be processed via a callback in
      Tor's event loop.  This is generally the best choice, since it
      avoids unexpected growth of the stack.

   - `DELIV_IMMEDIATE` -- causes messages to be processed immediately
      on the call stack when they are published.  This choice grows the
      stack, and can lead to unexpected complexity in the call graph.
      We should only use it when necessary.

   - `DELIV_NEVER` -- causes messages not to be delivered by the message
      dispatch system at all. Instead, some other part of the code must
      call dispatch_flush() to get the messages delivered.

See mainloop_pubsub.c and mainloop_pubsub.h for more information and
implementation details.

## Layers: Dispatch vs publish-subsubscribe vs mainloop.

At the lowest level, messages are sent via the "dispatcher" module in
@refdir{lib/dispatch}.  For performance, this dispatcher works with a
untyped messages.  Publishers, subscribers, channels, and messages are
distinguished by short integers.  Associated data is handled as
dynamically-typed data pointers, and its types are also stored as short
integers.

Naturally, this results in a type-unsafe C API, so most other modules
shouldn't invoke @refdir{lib/dispatch} directly.  At a higher level,
@refdir{lib/pubsub} defines a set of functions and macros that make
messages named and type-safe.  This is the one that other modules should
use when they want to send or receive a message.

The two modules above do not handle message delivery.  Instead, the
dispatch module takes a callback that it can invoke when a channel
becomes nonempty, and defines a dispatch_flush() function to deliver all
the messages queued in a channel.  The work of actually making sure that
dispatch_flush() is called when appropriate falls to the main loop,
which needs to integrate the message dispatcher with the rest of our
events and callbacks.  This work happens in mainloop_pubsub.c.


## How to publish and subscribe

This section gives an overview of how to make new messages and how to
use them.  For full details, see pubsub_macros.h.

Before anybody can publish or subscribe to a message, the message must
be declared, typically in a header.  This uses DECLARE_MESSAGE() or
DECLARE_MESSAGE_INT().

Only subsystems can publish or subscribe messages.  For more information
about the subsystems architecture, see @ref initialization.

To publish a message, you must:
   - Include the header that declares the message.
   - Declare a set of helper functions via DECLARE_PUBLISH().  These
     must be visible wherever you call PUBLISH().
   - Call PUBLISH() to actually send a message.
   - Connect your subsystem to the dispatcher by calling
     DISPATCH_ADD_PUB() from your subsystem's subsys_fns_t.add_pubsub
     callback.

To subscribe to a message, you must:
   - Include the header that declares the message.
   - Declare a callback function to be invoked when the message is delivered.
   - Use DISPATCH_SUBSCRIBE at file scope to define a set of wrapper
     functions to call your callback function with the appropriate type.
   - Connect your subsystem to the dispatcher by calling
     DISPATCH_ADD_SUB() from your subsystem's subsys_fns_t.add_pubsub
     callback.

Again, the file-level documentation for pubsub_macros.h describes how to
declare a message, how to publish it, and how to subscribe to it.

## Designing good messages

**Frequency**:
The publish-subscribe system uses a few function calls
and allocations for each message sent. This makes it unsuitable for
very-high-bandwidth events, like "receiving a single data cell" or "a
socket has become writable."  It's fine, however, for events that
ordinarily happen a bit less frequently than that, like a circuit
getting finished, a new connection getting opened, or so on.

**Semantics**:
A message should declare that something has happened or is happening,
not that something in particular should be done.

For example, suppose you want to set up a message so that onion services
clean up their replay caches whenever we're low on memory.  The event
should be something like `memory_low`, not `clean_up_replay_caches`.
The latter name would imply that the publisher knew who was subscribing
to the message and what they intended to do about it, which would be a
layering violation.
