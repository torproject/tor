@dir /lib/pubsub
@brief lib/pubsub: Publish-subscribe message passing.

This module wraps the \refdir{lib/dispatch} module, to provide a more
ergonomic and type-safe approach to message passing.

In general, we favor this mechanism for cases where higher-level modules
need to be notified when something happens in lower-level modules. (The
alternative would be calling up from the lower-level modules, which
would be error-prone; or maintaining lists of function-pointers, which
would be clumsy and tend to complicate the call graph.)

See pubsub.c for more information.

