# Tracing #

This document describes how the event tracing subsystem works in tor so
developers can add events to the code base but also hook them to an event
tracing framework (i.e. tracer).

## Basics ###

Tracing is separated in two different concepts. The tracing API and the
tracing probes.

The API is in `src/lib/trace/` which defines how to call tracepoints in the
tor code. Every C files should include `src/lib/trace/events.h" if they want
to call a tracepoint.

The probes are what actually record the tracepoint data. Because they often
need to access specific subsystem objects, the probes are within each
subsystem. They are defined in the `trace-probes-<subsystem>.c` files.

### Events ###

A trace event is basically a function from which we can pass any data that we
want to collect. In addition, we specify a context for the event such as the
subsystem and an event name.

A trace event in tor has the following standard format:

	tor_trace(subsystem, event\_name, args...)

The `subsystem` parameter is the name of the subsytem the trace event is in.
For example that could be "scheduler" or "vote" or "hs". The idea is to add
some context to the event so when we collect them we know where it's coming
from.

The `event\_name` is the name of the event which adds better semantic to the
event.

The `args` can be any number of arguments we want to collect.

Here is an example of a possible tracepoint in main():

	tor_trace(main, init_phase, argc)

The above is a tracepoint in the `main` subsystem with `init\_phase` as the
event name and the `int argc` is passed to the event as one argument.

How `argc` is collected or used has nothing to do with the instrumentation
(adding trace events to the code). It is the work of the tracer so this is why
the trace events and collection framework (tracer) are decoupled. You _can_
have trace events without a tracer.

### Instrumentation ###

In `src/lib/trace/events.h`, we map the high level `tor\_trace()` macro to one
or many enabled instrumentation.

Currently, we have 3 types of possible instrumentation:

1. Debug

  This will map every tracepoint to `log\_debug()`. However, none of the
  arguments will be passed on because we don't know their type nor the string
  format of the debug log. The output is standardized like this:

    [debug] __FUNC__: Tracepoint <event_name> from subsystem <subsystem> hit.

2. USDT

  User Statically-Defined Tracing (USDT) is a kind of probe which can be
  handled by a variety of tracers such as SystemTap, DTrace, perf, eBPF and
  ftrace.

  For each tracer, one will need to define the ABI in order for the tracer to
  be able to extract the data from the tracepoint objects. For instance, the
  tracer needs to know how to print the circuit state of a `circuit\_t`
  object.

3. LTTng-UST

  LTTng Userspace is a tracer that has it own type of instrumentation. The
  probe definitions are created within the C code and is strongly typed.

  For more information, see https://lttng.org/docs.

## Build System ##

This section describes how the instrumentation is integrated into the build
system of tor.

By default, every tracing events are disabled in tor that is `tor\_trace()` is
a NOP thus has no execution cost time.

To enable a specific instrumentation, there are configure options:

1. Debug: `--enable-tracing-instrumentation-debug`

2. USDT: `--enable-tracing-instrumentation-usdt`

3. LTTng: `--enable-tracing-instrumentation-lttng`

They can all be used together or independently. If one of them is set,
`HAVE\_TRACING` define is set. And for each instrumentation, a
`USE\_TRACING\_INSTRUMENTATION\_<type>` is set.

## Adding a Tracepoint ##

This is pretty easy. Let's say you want to add a trace event in
`src/feature/rend/rendcache.c`, you first need to include this file:

	#include "lib/trace/events.h"

Then, the `tor\_trace()` macro can be used with the specific format detailled
before in a previous section. As an example:

	tor_trace(hs, store_desc_as_client, desc, desc_id);

For `Debug` instrumentation, you have nothing else to do.

For `USDT`, instrumentation, you will need to define the probes in a way the
specific tracer can understand. For instance, SystemTap requires you to define
a `tapset` for each tracepoints.

For `LTTng`, you will need to define the probes in the
`trace-probes-<subsystem>.{c|h}` file. See the `trace-probes-circuit.{c|h}`
file as an example and https://lttng.org/docs/v2.11/#doc-instrumenting.

## Performance ##

A word about performance when a tracepoint is enabled. One of the goal of a
tracepoint (USDT, LTTng-UST, ...) is that they can be enabled or disabled. By
default, they are disabled which means the tracer will not record the data but
it has to do a check thus the cost is basically the one of a `branch`.

If enabled, then the performance depends on the tracer. In the case of
LTTng-UST, the event costs around 110nsec.
