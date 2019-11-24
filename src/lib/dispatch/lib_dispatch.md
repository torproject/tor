@dir /lib/dispatch
@brief lib/dispatch: In-process message delivery.

This module provides a general in-process "message dispatch" system in which
typed messages are sent on channels. The dispatch.h header has far more
information.

It is used by by \refdir{lib/pubsub} to implement our general
inter-module publish/subscribe system.

This is not a fancy multi-threaded many-to-many dispatcher as you may be used
to from more sophisticated architectures: this dispatcher is intended only
for use in improving Tor's architecture.

