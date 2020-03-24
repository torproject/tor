@page arch_goals High level code design practices

This page describes the high level design practices for Tor's code.
This design is a long-term goal of what we want our code to look like,
rather than a description of how it currently is.

Overall, we want various parts of tor's code to interact with each
other through a small number of interfaces.

We want to avoid having "god objects" or "god modules".  These are
objects or modules that know far too much about other parts of the
code.  God objects/modules are generally recognized to be an
antipattern of software design.

Historically, there have been modules in tor that have tended toward
becoming god modules.  These include modules that help more
specialized code communicate with the outside world: the configuration
and control modules, for example.  Others are modules that deal with
global state, initialization, or shutdown.

If a centralized module needs to invoke code in almost every other
module in the system, it is better if it exports a small, general
interface that other modules call.  The centralized module should not
explicitly call out to all the modules that interact with it.

Instead, modules that interact with the centralized module should call
registration interfaces.  These interfaces allow modules to register
handlers for things like configuration parsing and control command
execution.  (The config and control modules are examples of this.)
Alternatively, registration can happen through statically initialized
data structures.  (The subsystem mechanism is an example of this.)
