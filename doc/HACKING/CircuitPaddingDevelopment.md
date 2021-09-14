# Circuit Padding Developer Documentation

This document is written for researchers who wish to prototype and evaluate circuit-level padding defenses in Tor.

Written by Mike Perry and George Kadianakis.

# Table of Contents

- [0. Background](#0-background)
- [1. Introduction](#1-introduction)
    - [1.1. System Overview](#11-system-overview)
    - [1.2. Layering Model](#12-layering-model)
    - [1.3. Computation Model](#13-computation-model)
    - [1.4. Deployment Constraints](#14-other-deployment-constraints)
- [2. Creating New Padding Machines](#2-creating-new-padding-machines)
    - [2.1. Registering a New Padding Machine](#21-registering-a-new-padding-machine)
    - [2.2. Machine Activation and Shutdown](#22-machine-activation-and-shutdown)
- [3. Specifying Padding Machines](#3-specifying-padding-machines)
    - [3.1. Padding Machine States](#31-padding-machine-states)
    - [3.2. Padding Machine State Transitions](#32-padding-machine-state-transitions)
    - [3.3. Specifying Per-State Padding](#33-specifying-per-state-padding)
    - [3.4. Specifying Precise Cell Counts](#34-specifying-precise-cell-counts)
    - [3.5. Specifying Overhead Limits](#35-specifying-overhead-limits)
- [4. Evaluating Padding Machines](#4-evaluating-padding-machines)
    - [4.1. Pure Simulation](#41-pure-simulation)
    - [4.2. Testing in Chutney](#42-testing-in-chutney)
    - [4.3. Testing in Shadow](#43-testing-in-shadow)
    - [4.4. Testing on the Live Network](#44-testing-on-the-live-network)
- [5. Example Padding Machines](#5-example-padding-machines)
    - [5.1. Deployed Circuit Setup Machines](#51-deployed-circuit-setup-machines)
    - [5.2. Adaptive Padding Early](#52-adaptive-padding-early)
    - [5.3. Sketch of Tamaraw](#53-sketch-of-tamaraw)
    - [5.4. Other Padding Machines](#54-other-padding-machines)
- [6. Framework Implementation Details](#6-framework-implementation-details)
    - [6.1. Memory Allocation Conventions](#61-memory-allocation-conventions)
    - [6.2. Machine Application Events](#62-machine-application-events)
    - [6.3. Internal Machine Events](#63-internal-machine-events)
- [7. Future Features and Optimizations](#7-future-features-and-optimizations)
    - [7.1. Load Balancing and Flow Control](#71-load-balancing-and-flow-control)
    - [7.2. Timing and Queuing Optimizations](#72-timing-and-queuing-optimizations)
    - [7.3. Better Machine Negotiation](#73-better-machine-negotiation)
    - [7.4. Probabilistic State Transitions](#74-probabilistic-state-transitions)
    - [7.5. More Complex Pattern Recognition](#75-more-complex-pattern-recognition)
- [8. Open Research Problems](#8-open-research-problems)
    - [8.1. Onion Service Circuit Setup](#81-onion-service-circuit-setup)
    - [8.2. Onion Service Fingerprinting](#82-onion-service-fingerprinting)
    - [8.3. Open World Fingerprinting](#83-open-world-fingerprinting)
    - [8.4. Protocol Usage Fingerprinting](#84-protocol-usage-fingerprinting)
    - [8.5. Datagram Transport Side Channels](#85-datagram-transport-side-channels)
- [9. Must Read Papers](#9-must-read-papers)


## 0. Background

Tor supports both connection-level and circuit-level padding, and both
systems are live on the network today. The connection-level padding behavior
is described in [section 2 of
padding-spec.txt](https://github.com/torproject/torspec/blob/master/padding-spec.txt#L47). The
circuit-level padding behavior is described in [section 3 of
padding-spec.txt](https://github.com/torproject/torspec/blob/master/padding-spec.txt#L282).

These two systems are orthogonal and should not be confused. The
connection-level padding system is only active while the TLS connection is
otherwise idle. Moreover, it regards circuit-level padding as normal data
traffic, and hence while the circuit-level padding system is actively padding,
the connection-level padding system will not add any additional overhead.

While the currently deployed circuit-level padding behavior is quite simple,
it is built on a flexible framework. This framework supports the description
of event-driven finite state machine by filling in fields of a simple C
structure, and is designed to support any delay-free statistically shaped
cover traffic on individual circuits, with cover traffic flowing to and from a
node of the implementor's choice (Guard, Middle, Exit, Rendezvous, etc).

This class of system was first proposed in
[Timing analysis in low-latency mix networks: attacks and defenses](https://www.freehaven.net/anonbib/cache/ShWa-Timing06.pdf)
by Shmatikov and Wang, and extended for the website traffic fingerprinting
domain by Juarez et al. in
[Toward an Efficient Website Fingerprinting Defense](http://arxiv.org/pdf/1512.00524). The
framework also supports fixed parameterized probability distributions, as
used in [APE](https://www.cs.kau.se/pulls/hot/thebasketcase-ape/) by Tobias
Pulls, and many other features.

This document describes how to use Tor's circuit padding framework to
implement and deploy novel delay-free cover traffic defenses.

## 1. Introduction

The circuit padding framework is the official way to implement padding
defenses in Tor. It may be used in combination with application-layer
defenses, and/or obfuscation defenses, or on its own.

Its current design should be enough to deploy most defenses without
modification, but you can extend it to [provide new
features](#7-future-features-and-optimizations) as well.

### 1.1. System Overview

Circuit-level padding can occur between Tor clients and relays at any hop of
one of the client's circuits. Both parties need to support the same padding
mechanisms for the system to work, and the client must enable it.

We added a padding negotiation relay cell to the Tor protocol that clients use
to ask a relay to start padding, as well as a torrc directive for researchers
to pin their clients' relay selection to the subset of Tor nodes that
implement their custom defenses, to support ethical live network testing and
evaluation.

Circuit-level padding is performed by 'padding machines'. A padding machine is
a finite state machine. Every state specifies a different form of
padding style, or stage of padding, in terms of inter-packet timings and total
packet counts.

Padding state machines are specified by filling in fields of a C structure,
which specifies the transitions between padding states based on various events,
probability distributions of inter-packet delays, and the conditions under
which padding machines should be applied to circuits.

This compact C structure representation is designed to function as a
microlanguage, which can be compiled down into a
bitstring that [can be tuned](#13-computation-model) using various
optimization methods (such as gradient descent, GAs, or GANs), either in
bitstring form or C struct form.

The event driven, self-contained nature of this framework is also designed to
make [evaluation](#4-evaluating-padding-machines) both expedient and rigorously
reproducible.

This document covers the engineering steps to write, test, and deploy a
padding machine, as well as how to extend the framework to support new machine
features.

If you prefer to learn by example, you may want to skip to either the
[QuickStart Guide](CircuitPaddingQuickStart.md), and/or [Section
5](#5-example-padding-machines) for example machines to get you up and running
quickly.

### 1.2. Layering Model

The circuit padding framework is designed to provide one layer in a layered
system of interchangeable components.

The circuit padding framework operates at the Tor circuit layer. It only deals
with the inter-cell timings and quantity of cells sent on a circuit. It can
insert cells on a circuit in arbitrary patterns, and in response to arbitrary
conditions, but it cannot delay cells. It also does not deal with packet
sizes, how cells are packed into TLS records, or ways that the Tor protocol
might be recognized on the wire.

The problem of differentiating Tor traffic from non-Tor traffic based on
TCP/TLS packet sizes, initial handshake patterns, and DPI characteristics is the
domain of [pluggable
transports](https://gitlab.torproject.org/tpo/anti-censorship/team/-/wikis/AChildsGardenOfPluggableTransports),
which may optionally be used in conjunction with this framework (or without
it).

This document focuses primarily on the circuit padding framework's cover
traffic features, and will only briefly touch on the potential obfuscation and
application layer coupling points of the framework. Explicit layer coupling
points can be created by adding either new [machine application
events](#62-machine-application-events) or new [internal machine
events](#63-internal-machine-events) to the circuit padding framework, so that
your padding machines can react to events from other layers.

### 1.3. Computation Model

The circuit padding framework is designed to support succinctly specified
defenses that can be tuned through [computer-assisted
optimization](#4-evaluating-padding-machines).

We chose to generalize the original [Adaptive Padding 2-state
design](https://www.freehaven.net/anonbib/cache/ShWa-Timing06.pdf) into an
event-driven state machine because state machines are the simplest form of
sequence recognition devices from [automata
theory](https://en.wikipedia.org/wiki/Finite-state_machine).

Most importantly: this framing allows cover traffic defenses to be modeled as
an optimization problem search space, expressed as fields of a C structure
(which is simultaneously a compact opaque bitstring as well as a symbolic
vector in an abstract feature space). This kind of space is particularly well
suited to search by gradient descent, GAs, and GANs.

When performing this optimization search, each padding machine should have a
fitness function, which will allow two padding machines to be compared for
relative effectiveness. Optimization searches work best if this fitness can be
represented as a single number, for example the total amount by which it
reduces the [Balanced
Accuracy](https://en.wikipedia.org/wiki/Precision_and_recall#Imbalanced_Data)
of an adversary's classifier, divided by an amount of traffic overhead.

Before you begin the optimization phase for your defense, you should
also carefully consider the [features and
optimizations](#7-future-features-and-optimizations) that we suspect will be
useful, and also see if you can come up with any more. You should similarly be
sure to restrict your search space to avoid areas of the bitstring/feature
vector that you are sure you will not need. For example, some
[applications](#8-open-research-problems) may not need the histogram
accounting used by Adaptive Padding, but might need to add other forms of
[pattern recognition](#75-more-complex-pattern-recognition) to react to
sequences that resemble HTTP GET and HTTP POST.

### 1.4. Other Deployment Constraints

The framework has some limitations that are the result of deliberate
choices. We are unlikely to deploy defenses that ignore these limitations.

In particular, we have deliberately not provided any mechanism to delay actual
user traffic, even though we are keenly aware that if we were to support
additional delay, defenses would be able to have [more success with less
bandwidth
overhead](https://freedom.cs.purdue.edu/anonymity/trilemma/index.html).

In the website traffic fingerprinting domain, [provably optimal
defenses](https://www.cypherpunks.ca/~iang/pubs/webfingerprint-ccs14.pdf)
achieve their bandwidth overhead bounds by ensuring that a non-empty queue is
maintained, by rate limiting traffic below the actual throughput of a circuit.
For optimal results, this queue must avoid draining to empty, and yet it
must also be drained fast enough to avoid tremendous queue overhead in fast
Tor relays, which carry hundreds of thousands of circuits simultaneously.

Unfortunately, Tor's end-to-end flow control is not congestion control. Its
window sizes are currently fixed. This means there is no signal when queuing
occurs, and thus no ability to limit queue size through pushback. This means
there is currently no way to do the fine-grained queue management necessary to
create such a queue and rate limit traffic effectively enough to keep this
queue from draining to empty, without also risking that aggregate queuing
would cause out-of-memory conditions on fast relays.

It may be possible to create a congestion control algorithm that can support
such fine grained queue management, but this is a [deeply unsolved area of
research](https://lists.torproject.org/pipermail/tor-dev/2018-November/013562.html).

Even beyond these major technical hurdles, additional latency is also
unappealing to the wider Internet community, for the simple reason that
bandwidth [continues to increase
exponentially](https://ipcarrier.blogspot.com/2014/02/bandwidth-growth-nearly-what-one-would.html)
where as the speed of light is fixed. Significant engineering effort has been
devoted to optimizations that reduce the effect of latency on Internet
protocols. To go against this trend would ensure our irrelevance to the wider
conversation about traffic analysis defenses for low latency Internet protocols.

On the other hand, through [load
balancing](https://gitweb.torproject.org/torspec.git/tree/proposals/265-load-balancing-with-overhead.txt)
and [circuit multiplexing strategies](https://bugs.torproject.org/29494), we
believe it is possible to add significant bandwidth overhead in the form of
cover traffic, without significantly impacting end-user performance.

For these reasons, we believe the trade-off should be in favor of adding more
cover traffic, rather than imposing queuing memory overhead and queuing delay.

As a last resort for narrowly scoped application domains (such as
shaping Tor service-side onion service traffic to look like other websites or
different application-layer protocols), delay *may* be added at the
[application layer](https://petsymposium.org/2017/papers/issue2/paper54-2017-2-source.pdf).
Any additional cover traffic required by such defenses should still be
added at the circuit padding layer using this framework, to provide
engineering efficiency through loose layer coupling and component re-use, as
well as to provide additional gains against [low
resolution](https://github.com/torproject/torspec/blob/master/padding-spec.txt#L47)
end-to-end traffic correlation.

Because such delay-based defenses will impact performance significantly more
than simply adding cover traffic, they must be optional, and negotiated by
only specific application layer endpoints that want them. This will have
consequences for anonymity sets and base rates, if such traffic shaping and
additional cover traffic is not very carefully constructed.

In terms of acceptable overhead, because Tor onion services
[currently use](https://metrics.torproject.org/hidserv-rend-relayed-cells.html)
less than 1% of the
[total consumed bandwidth](https://metrics.torproject.org/bandwidth-flags.html)
of the Tor network, and because onion services exist to provide higher
security as compared to Tor Exit traffic, they are an attractive target for
higher-overhead defenses. We encourage researchers to target this use case
for defenses that require more overhead, and/or for the deployment of
optional negotiated application-layer delays on either the server or the
client side.

## 2. Creating New Padding Machines

This section explains how to use the existing mechanisms in Tor to define a
new circuit padding machine.  We assume here that you know C, and are at
least somewhat familiar with Tor development.  For more information on Tor
development in general, see the other files in doc/HACKING/ in a recent Tor
distribution.

Again, if you prefer to learn by example, you may want to skip to either the
[QuickStart Guide](CircuitPaddingQuickStart.md), and/or [Section
5](#5-example-padding-machines) for example machines to get up and running
quickly.

To create a new padding machine, you must:

  1. Define your machine using the fields of a heap-allocated
     `circpad_machine_spec_t` C structure.

  2. Register this object in the global list of available padding machines,
     using `circpad_register_padding_machine()`.

  3. Ensure that your machine is properly negotiated under your desired
     circuit conditions.

### 2.1. Registering a New Padding Machine

Again, a circuit padding machine is designed to be specified entirely as a [single
C structure](#13-computation-model).

Your machine definitions should go into their own functions in
[circuitpadding_machines.c](https://github.com/torproject/tor/blob/master/src/core/or/circuitpadding_machines.c). For
details on all of the fields involved in specifying a padding machine, see
[Section 3](#3-specifying-padding-machines).

You must register your machine in `circpad_machines_init()` in
[circuitpadding.c](https://github.com/torproject/tor/blob/master/src/core/or/circuitpadding.c). To
add a new padding machine specification, you must allocate a
`circpad_machine_spec_t` on the heap with `tor_malloc_zero()`, give it a
human readable name string, and a machine number equivalent to the number of
machines in the list, and register the structure using
`circpad_register_padding_machine()`.

Each machine must have a client instance and a relay instance. Register your
client-side machine instance in the `origin_padding_machines` list, and your
relay side machine instance in the `relay_padding_machines` list. Once you
have registered your instance, you do not need to worry about deallocation;
this is handled for you automatically.

Both machine lists use registration order to signal machine precedence for a
given `machine_idx` slot on a circuit. This means that machines that are
registered last are checked for activation *before* machines that are
registered first. (This reverse precedence ordering allows us to
deprecate older machines simply by adding new ones after them.)

### 2.2. Machine Activation and Shutdown

After a machine has been successfully registered with the framework, it will
be instantiated on any client-side circuits that support it. Only client-side
circuits may initiate padding machines, but either clients or relays may shut
down padding machines.

#### 2.2.1. Machine Application Conditions

The
[circpad_machine_conditions_t conditions field](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L641)
of your `circpad_machine_spec_t` machine definition instance controls the
conditions under which your machine will be attached and enabled on a Tor
circuit, and when it gets shut down.

*All* of your explicitly specified conditions in
`circpad_machine_spec_t.conditions` *must* be met for the machine to be
applied to a circuit. If *any* condition ceases to be met, then the machine
is shut down.  (This is checked on every event that arrives, even if the
condition is unrelated to the event.)
Another way to look at this is that
all specified conditions must evaluate to true for the entire duration that
your machine is running. If any are false, your machine does not run (or
stops running and shuts down).

In particular, as part of the
[circpad_machine_conditions_t structure](https://github.com/torproject/tor/blob/master/src/core/or/circuitpadding.h#L149),
the circuit padding subsystem gives the developer the option to enable a
machine based on:
  - The
    [length](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L157)
    on the circuit (via the `min_hops` field).
  - The
    [current state](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L174)
    of the circuit, such as streams, relay_early, etc. (via the
    `circpad_circuit_state_t state_mask` field).
  - The
    [purpose](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L178)
    (i.e. type) of the circuit (via the `circpad_purpose_mask_t purpose_mask`
    field).

This condition mechanism is the preferred way to determine if a machine should
apply to a circuit. For information about potentially useful conditions that
we have considered but have not yet implemented, see [Section
7.3](#73-better-machine-negotiation). We will happily accept patches for those
conditions, or any for other additional conditions that are needed for your
use case.

#### 2.2.2. Detecting and Negotiating Machine Support

When a new machine specification is added to Tor (or removed from Tor), you
should bump the Padding subprotocol version in `src/core/or/protover.c`, add a
field to `protover_summary_flags_t` in `or.h`, and set this field in
`memoize_protover_summary()` in versions.c. This new field must then be
checked in `circpad_node_supports_padding()` in `circuitpadding.c`.

Note that this protocol version update and associated support check is not
necessary if your experiments will *only* be using your own relays that
support your own padding machines. This can be accomplished by using the
`MiddleNodes` directive; see [Section 4](#4-evaluating-padding-machines) for more information.

If the protocol support check passes for the circuit, then the client sends a
`RELAY_COMMAND_PADDING_NEGOTIATE` cell towards the
`circpad_machine_spec_t.target_hop` relay, and immediately enables the
padding machine, and may begin sending padding. (The framework does not wait
for the `RELAY_COMMAND_PADDING_NEGOTIATED` response to begin padding,
so that we can
switch between machines rapidly.)

#### 2.2.3. Machine Shutdown Mechanisms

Padding machines can be shut down on a circuit in three main ways:
  1. During a `circpad_machine_event` callback, when
     `circpad_machine_spec_t.conditions` no longer applies (client side)
  2. After a transition to the CIRCPAD_STATE_END, if
     `circpad_machine_spec_t.should_negotiate_end` is set (client or relay
     side)
  3. If there is a `RELAY_COMMAND_PADDING_NEGOTIATED` error response from the
     relay during negotiation.

Each of these cases causes the originating node to send a relay cell towards
the other side, indicating that shutdown has occurred. The client side sends
`RELAY_COMMAND_PADDING_NEGOTIATE`, and the relay side sends
`RELAY_COMMAND_PADDING_NEGOTIATED`.

Because padding from malicious exit nodes can be used to construct active
timing-based side channels to malicious guard nodes, the client checks that
padding-related cells only come from relays with active padding machines.
For this reason, when a client decides to shut down a padding machine,
the framework frees the mutable `circuit_t.padding_info`, but leaves the
`circuit_t.padding_machine` pointer set until the
`RELAY_COMMAND_PADDING_NEGOTIATED` response comes back, to ensure that any
remaining in-flight padding packets are recognized a valid. Tor does
not yet close circuits due to violation of this property, but the
[vanguards addon component "bandguard"](https://github.com/mikeperry-tor/vanguards/blob/master/README_TECHNICAL.md#the-bandguards-subsystem)
does.

As an optimization, a client may replace a machine with another, by
sending a `RELAY_COMMAND_PADDING_NEGOTIATE` cell to shut down a machine, and
immediately sending a `RELAY_COMMAND_PADDING_NEGOTIATE` to start a new machine
in the same index, without waiting for the response from the first negotiate
cell.

Unfortunately, there is a known bug as a consequence of this optimization. If
your machine depends on repeated shutdown and restart of the same machine
number on the same circuit, please see [Bug
30922](https://bugs.torproject.org/30992). Depending on your use case, we may
need to fix that bug or help you find a workaround. See also [Section
6.1.3](#613-deallocation-and-shutdown) for some more technical details on this
mechanism.


## 3. Specifying Padding Machines

By now, you should understand how to register, negotiate, and control the
lifetime of your padding machine, but you still don't know how to make it do
anything yet. This section should help you understand how to specify how your
machine reacts to events and adds padding to the wire.

If you prefer to learn by example first instead, you may wish to skip to
[Section 5](#5-example-padding-machines).


A padding machine is specified by filling in an instance of
[circpad_machine_spec_t](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L605). Instances
of this structure specify the precise functionality of a machine: it's
what the circuit padding developer is called to write. These instances
are created only at startup, and are referenced via `const` pointers during
normal operation.

In this section we will go through the most important elements of this
structure.

### 3.1. Padding Machine States

A padding machine is a finite state machine where each state
specifies a different style of padding.

As an example of a simple padding machine, you could have a state machine
with the following states: `[START] -> [SETUP] -> [HTTP] -> [END]` where the
`[SETUP]` state pads in a way that obfuscates the ''circuit setup'' of Tor,
and the `[HTTP]` state pads in a way that emulates a simple HTTP session. Of
course, padding machines can be more complicated than that, with dozens of
states and non-trivial transitions.

Padding developers encode the machine states in the
[circpad_machine_spec_t structure](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L655). Each
machine state is described by a
[circpad_state_t structure](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L273)
and each such structure specifies the style and amount of padding to be sent,
as well as the possible state transitions.

The function `circpad_machine_states_init()` must be used for allocating and
initializing the `circpad_machine_spec_t.states` array before states and
state transitions can be defined, as some of the state object has non-zero
default values.

### 3.2. Padding Machine State Transitions

As described above, padding machines can have multiple states, to
support different forms of padding. Machines can transition between
states based on events that occur either on the circuit level or on
the machine level.

State transitions are specified using the
[next_state field](https://github.com/torproject/tor/blob/master/src/core/or/circuitpadding.h#L381)
of the `circpad_state_t` structure. As a simple example, to transition
from state `A` to state `B` when event `E` occurs, you would use the
following code: `A.next_state[E] = B`.

#### 3.2.1. State Transition Events

Here we will go through
[the various events](https://github.com/torproject/tor/blob/master/src/core/or/circuitpadding.h#L30)
that can be used to transition between states:

* Circuit-level events
  * `CIRCPAD_EVENT_NONPADDING_RECV`: A non-padding cell is received
  * `CIRCPAD_EVENT_NONPADDING_SENT`: A non-adding cell is sent
  * `CIRCPAD_EVENT_PADDING_SENT`: A padding cell is sent
  * `CIRCPAD_EVENT_PADDING_RECV`: A padding cell is received
* Machine-level events
  * `CIRCPAD_EVENT_INFINITY`: Tried to schedule padding using the ''infinity bin''.
  * `CIRCPAD_EVENT_BINS_EMPTY`: All histogram bins are empty (out of tokens)
  * `CIRCPAD_EVENT_LENGTH_COUNT`: State has used all its padding capacity (see `length_dist` below)

### 3.3. Specifying Per-State Padding

Each state of a padding machine specifies either:
  * A padding histogram describing inter-transmission delays between cells;
d     OR
  * A parameterized delay probability distribution for inter-transmission
    delays between cells.

Either mechanism specifies essentially the *minimum inter-transmission time*
distribution. If non-padding traffic does not get transmitted from this
endpoint before the delay value sampled from this distribution expires, a
padding packet is sent.

The choice between histograms and probability distributions can be subtle. A
rule of thumb is that probability distributions are easy to specify and
consume very little memory, but might not be able to describe certain types
of complex padding logic. Histograms, in contrast, can support precise
packet-count oriented or multimodal delay schemes, and can use token removal
logic to reduce overhead and shape the total padding+non-padding inter-packet
delay distribution towards an overall target distribution.

We suggest that you start with a probability distribution if possible, and
you move to a histogram-based approach only if a probability distribution
does not suit your needs.

#### 3.3.1. Padding Probability Distributions

The easiest, most compact way to schedule padding using a machine state is to
use a probability distribution that specifies the possible delays. That can
be done
[using the circpad_state_t fields](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L339)
`iat_dist`, `dist_max_sample_usec` and `dist_added_shift_usec`.

The Tor circuit padding framework
[supports multiple types](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L214)
of probability distributions, and the developer should use the
[circpad_distribution_t structure](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L240)
to specify them as well as the required parameters.

#### 3.3.2. Padding Histograms

A more advanced way to schedule padding is to use a ''padding
histogram''. The main advantages of a histogram are that it allows you to
specify distributions that are not easily parameterized in closed form, or
require specific packet counts at particular time intervals. Histograms also
allow you to make use of an optional traffic minimization and shaping
optimization called *token removal*, which is central to the original
[Adaptive Padding](https://www.freehaven.net/anonbib/cache/ShWa-Timing06.pdf)
concept.

If a histogram is used by a state (as opposed to a fixed parameterized
distribution), then the developer must use the
[histogram-related fields](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L285)
of the `circpad_state_t` structure.

The width of a histogram bin specifies the range of inter-packet delay times,
whereas its height specifies the amount of tokens in each bin. To sample a
padding delay from a histogram, we first randomly pick a bin (weighted by the
amount of tokens in each bin) and then sample a delay from within that bin by
picking a uniformly random delay using the width of the bin as the range.

Each histogram also has an ''infinity bin'' as its final bin.  If the
''infinity bin'' is chosen,
we don't schedule any padding (i.e., we schedule padding with
infinite delay). If the developer does not want infinite delay, they
should not give any tokens to the ''infinity bin''.

If a token removal strategy is specified (via the
`circpad_state_t.token_removal` field), each time padding is sent using a
histogram, the padding machine will remove a token from the appropriate
histogram bin whenever this endpoint sends *either a padding packet or a
non-padding packet*. The different removal strategies govern what to do when
the bin corresponding to the current inter-packet delay is empty.

Token removal is optional. It is useful if you want to do things like specify
a burst should be at least N packets long, and you only want to add padding
packets if there are not enough non-padding packets. The cost of doing token
removal is additional memory allocations for making per-circuit copies of
your histogram that can be modified.

### 3.4. Specifying Precise Cell Counts

Padding machines should be able to specify the exact amount of padding they
send. For histogram-based machines this can be done using a specific amount
of tokens, but another (and perhaps easier) way to do this, is to use the
[length_dist field](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.h#L362)
of the `circpad_state_t` structure.

The `length_dist` field is basically a probability distribution similar to the
padding probability distributions, which applies to a specific machine state
and specifies the amount of padding we are willing to send during that state.
This value gets sampled when we transition to that state (TODO document this
in the code).

### 3.5. Specifying Overhead Limits

Separately from the length counts, it is possible to rate limit the overhead
percentage of padding at both the global level across all machines, and on a
per-machine basis.

At the global level, the overhead percentage of all circuit padding machines
as compared to total traffic can be limited through the Tor consensus
parameter `circpad_global_max_padding_pct`. This overhead is defined as the
percentage of padding cells *sent* out of the sum of non padding and padding
cells *sent*, and is applied *only after* at least
`circpad_global_allowed_cells` padding cells are sent by that relay or client
(to allow for small bursts of pure padding on otherwise idle or freshly
restarted relays). When both of these limits are hit by a relay or client, no
further padding cells will be sent, until sufficient non-padding traffic is
sent to cause the percentage of padding traffic to fall back below the
threshold.

Additionally, each individual padding machine can rate limit itself by
filling in the fields `circpad_machine_spec_t.max_padding_percent` and
`circpad_machine_spec_t.allowed_padding_count`, which behave identically to
the consensus parameters, but only apply to that specific machine.

## 4. Evaluating Padding Machines

One of the goals of the circuit padding framework is to provide improved
evaluation and scientific reproducibility for lower cost. This includes both
the [choice](#13-computation-model) of the compact C structure representation
(which has an easy-to-produce bitstring representation for optimization by
gradient descent, GAs, or GANs), as well as rapid prototyping and evaluation.

So far, whenever evaluation cost has been a barrier, each research group has
developed their own ad-hoc packet-level simulators of various padding
mechanisms for evaluating website fingerprinting attacks and defenses. The
process typically involves doing a crawl of Alexa top sites over Tor, and
recording the Tor cell count and timing information for each page in the
trace. These traces are then fed to simulations of defenses, which output
modified trace files.

Because no standardized simulation and evaluation mechanism exists, it is
often hard to tell if independent implementations of various attacks and
defenses are in fact true-to-form or even properly calibrated for direct
comparison, and discrepancies in results across the literature suggests
this is not always so.

Our preferred outcome with this framework is that machines are tuned
and optimized on a tracing simulator, but that the final results come from
an actual live network test of the defense. The traces from this final crawl
should be preserved as artifacts to be run on the simulator and reproduced
on the live network by future papers, ideally in journal venues that have an
artifact preservation policy.

### 4.1. Pure Simulation

When doing initial tuning of padding machines, especially in adversarial
settings, variations of a padding machine defense may need to be applied to
network activity hundreds or even millions of times. The wall-clock time
required to do this kind of tuning using live testing or even Shadow network
emulation may often be prohibitive.

To help address this, and to better standardize results, Tobias Pulls has
implemented a [circpad machine trace simulator](https://github.com/pylls/circpad-sim),
which uses Tor's unit test framework to simulate applying padding machines to
circuit packet traces via a combination of Tor patches and python scripts. This
simulator can be used to record traces from clients, Guards, Middles, Exits,
and any other hop in the path, only for circuits that are run by the
researcher. This makes it possible to safely record baseline traces and
ultimately even mount passive attacks on the live network, without impacting
or recording any normal user traffic.

In this way, a live crawl of the Alexa top sites could be performed once, to
produce a standard "undefended" corpus. Padding machines can be then quickly
evaluated and tuned on these simulated traces in a standardized way, and then
the results can then be [reproduced on the live Tor
network](#44-Testing-on-the-Live-Network) with the machines running on your own relays.

Please be mindful of the Limitations section of the simulator documentation,
however, to ensure that you are aware of the edge cases and timing
approximations that are introduced by this approach.

### 4.2. Testing in Chutney

The Tor Project provides a tool called
[Chutney](https://github.com/torproject/chutney/) which makes it very easy to
setup private Tor networks. While getting it work for the first time might
take you some time of doc reading, the final result is well worth it for the
following reasons:

- You control all the relays and hence you have greater control and debugging
  capabilities.
- You control all the relays and hence you can toggle padding support on/off
  at will.
- You don't need to be cautious about overhead or damaging the real Tor
  network during testing.
- You don't even need to be online; you can do all your testing offline over
  localhost.

A final word of warning here is that since Chutney runs over localhost, the
packet latencies and delays are completely different from the real Tor
network, so if your padding machines rely on real network timings you will
get different results on Chutney. You can work around this by using a
different set of delays if Chutney is used, or by moving your padding
machines to the real network when you want to do latency-related testing.

### 4.3. Testing in Shadow

[Shadow](https://shadow.github.io/) is an environment for running entire Tor
network simulations, similar to Chutney, but designed to be both more memory
efficient, as well as provide an accurate Tor network topology and latency
model.

While Shadow is significantly more memory efficient than Chutney, and can make
use of extremely accurate Tor network capacity and latency models, it will not
be as fast or efficient as the [circpad trace simulator](https://github.com/pylls/circpad-sim),
if you need to do many many iterations of an experiment to tune your defense.

### 4.4. Testing on the Live Network

Live network testing is the gold standard for verifying that any attack or
defense is behaving as expected, to minimize the influence of simplifying
assumptions.

However, it is not ethical, or necessarily possible, to run high-resolution
traffic analysis attacks on the entire Tor network. But it is both ethical
and possible to run small scale experiments that target only your own
clients, who will only use your own Tor relays that support your new padding
machines.

We provide the `MiddleNodes` torrc directive to enable this, which will allow
you to specify the fingerprints and/or IP netmasks of relays to be used in
the second hop position. Options to restrict other hops also exist, if your
padding system is padding to a different hop. The `HSLayer2Nodes` option
overrides the `MiddleNodes` option for onion service circuits, if both are
set. (The
[vanguards addon](https://github.com/mikeperry-tor/vanguards/README_TECHNICAL.md)
will set `HSLayer2Nodes`.)

When you run your own clients, and use MiddleNodes to restrict your clients
to use your relays, you can perform live network evaluations of a defense
applied to whatever traffic crawl or activity your clients do.

## 5. Example Padding Machines

### 5.1. Deployed Circuit Setup Machines

Tor currently has two padding machines enabled by default, which aim to hide
certain features of the client-side onion service circuit setup protocol. For
more details on their precise goal and function, please see
[proposal 302](https://github.com/torproject/torspec/blob/master/proposals/302-padding-machines-for-onion-clients.txt)
. In this section we will go over the code of those machines to clarify some
of the engineering parts:

#### 5.1.1. Overview

The codebase of proposal 302 can be found in
[circuitpadding_machines.c](https://github.com/torproject/tor/blob/master/src/core/or/circuitpadding_machines.c)
and specifies four padding machines:

- The [client-side introduction](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L60) circuit machine.
- The [relay-side introduction](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L146) circuit machine.
- The [client-side rendezvous](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L257) circuit machine
- The [relay-side rendezvous](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L374) circuit machine.

Each of those machines has its own setup function, and
[they are all initialized](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding.c#L2718)
by the circuit padding framework. To understand more about them, please
carefully read the individual setup function for each machine which are
fairly well documented. Each function goes through the following steps:
- Machine initialization
  - Give it a [name](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L70)
  - Specify [which hop](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L73) the padding should go to
  - Specify whether it should be [client-side](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L75) or relay-side.
- Specify for [which types of circuits](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L78) the machine should apply
- Specify whether the circuits should be [kept alive](https://github.com/torproject/tor/blob/master/src/core/or/circuitpadding_machines.c#L112) until the machine finishes padding.
- Sets [padding limits](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L116) to avoid too much overhead in case of bugs or errors.
- Setup [machine states](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L120)
   - Specify [state transitions](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L123).
- Finally [register the machine](https://github.com/torproject/tor/blob/35e978da61efa04af9a5ab2399dff863bc6fb20a/src/core/or/circuitpadding_machines.c#L137) to the global machine list

### 5.2. Adaptive Padding Early

[Adaptive Padding Early](https://www.cs.kau.se/pulls/hot/thebasketcase-ape/)
is a variant of Adaptive Padding/WTF-PAD that does not use histograms or token
removal to shift padding distributions, but instead uses fixed parameterized
distributions to specify inter-packet timing thresholds for burst and gap
inter-packet delays.

Tobias Pulls's [QuickStart Guide](CircuitPaddingQuickStart.md) describes how
to get this machine up and running, and has links to branches with a working
implementation.

### 5.3. Sketch of Tamaraw

The [Tamaraw defense
paper](https://www.cypherpunks.ca/~iang/pubs/webfingerprint-ccs14.pdf) is the
only defense to date that provides a proof of optimality for the finite-length
website traffic fingerprinting domain. These bounds assume that a defense is
able to perform a full, arbitrary transform of a trace that is under a fixed
number of packets in length.

The key insight to understand Tamaraw's optimality is that it achieves one
such optimal transform by delaying traffic below a circuit's throughput. By
doing this, it creates a queue that is rarely empty, allowing it to produce
a provably optimal transform with minimal overhead. As [Section
1.4](#14-other-deployment-constraints) explains, this queue
cannot be maintained on the live Tor network without risk of out-of-memory
conditions at relays.

However, if the queue is not maintained in the Tor network, but instead by the
application layer, it could be deployed by websites that opt in to using it.

In this case, the application layer component would do *optional* constant
rate shaping, negotiated between a web browser and a website. The Circuit
Padding Framework can then easily fill in any missing gaps of cover traffic
packets, and also ensure that only a fixed length number of packets are sent
in total.

However, for such a defense to be safe, additional care must be taken to
ensure that the resulting traffic pattern still has a large
anonymity/confusion set with other traces on the live network.

Accomplishing this is an unsolved problem.

### 5.4. Other Padding Machines

Our partners in this project at RIT have produced a couple prototypes, based
on their published research designs
[REB and RBB](https://www.researchgate.net/publication/329743510_UNDERSTANDING_FEATURE_DISCOVERY_IN_WEBSITE_FINGERPRINTING_ATTACKS).

As [their writeup
explains](https://github.com/notem/tor-rbp-padding-machine-doc), because RBB
uses delay, the circuit padding machine that they made is a no-delay version.

They also ran into an issue with the 0-delay timing workaround for [bug
31653](https://bugs.torproject.org/31653). Keep an eye on that bug for updates
with improved workarounds/fixes.

Their code is [available on github](https://github.com/notem/tor/tree/circuit_padding_rbp_machine).


## 6. Framework Implementation Details

If you need to add additional events, conditions, or other features to the
circuit padding framework, then this section is for you.

### 6.1. Memory Allocation Conventions

If the existing circuit padding features are sufficient for your needs, then
you do not need to worry about memory management or pointer lifespans. The
circuit padding framework should take care of this for you automatically.

However, if you need to add new padding machine features to support your
padding machines, then it will be helpful to understand how circuits
correspond to the global machine definitions, and how mutable padding machine
memory is managed.

#### 6.1.1. Circuits and Padding Machines

In Tor, the
[circuit_t structure](https://github.com/torproject/tor/blob/master/src/core/or/circuit_st.h)
is the superclass structure for circuit-related state that is used on both
clients and relays. On clients, the actual datatype of the object pointed to
by `circuit_t *` is the subclass structure
[origin_circuit_t](https://github.com/torproject/tor/blob/master/src/core/or/origin_circuit_st.h). The
macros `CIRCUIT_IS_ORIGIN()` and `TO_ORIGIN_CIRCUIT()` are used to determine
if a circuit is a client-side (origin) circuit and to cast the pointer safely
to `origin_circuit_t *`.

Because circuit padding machines can be present at both clients and relays,
the circuit padding fields are stored in the `circuit_t *` superclass
structure. Notice that there are actually two sets of circuit padding fields:
a `const circpad_machine_spec_t *` array, and a `circpad_machine_runtime_t *`
array. Each of these arrays holds at most two elements, as there can be at
most two padding machines on each circuit.

The `const circpad_machine_spec_t *` points to a globally allocated machine
specification. These machine specifications are
allocated and set up during Tor program startup, in `circpad_machines_init()`
in
[circuitpadding.c](https://github.com/torproject/tor/blob/master/src/core/or/circuitpadding.c). Because
the machine specification object is shared by all circuits, it must not be
modified or freed until program exit (by `circpad_machines_free()`). The
`const` qualifier should enforce this at compile time.

The `circpad_machine_runtime_t *` array member points to the mutable runtime
information for machine specification at that same array index. This runtime
structure keeps track of the current machine state, packet counts, and other
information that must be updated as the machine operates. When a padding
machine is successfully negotiated `circpad_setup_machine_on_circ()` allocates
the associated runtime information.

#### 6.1.2. Histogram Management

If a `circpad_state_t` of a machine specifies a `token_removal` strategy
other than `CIRCPAD_TOKEN_REMOVAL_NONE`, then every time
there is a state transition into this state, `circpad_machine_setup_tokens()`
will copy the read-only `circpad_state_t.histogram` array into a mutable
version at `circpad_machine_runtime_t.histogram`. This mutable copy is used
to decrement the histogram bin accounts as packets are sent, as per the
specified token removal strategy.

When the state machine transitions out of this state, the mutable histogram copy is freed
by this same `circpad_machine_setup_tokens()` function.

#### 6.1.3. Deallocation and Shutdown

As an optimization, padding machines can be swapped in and out by the client
without waiting a full round trip for the relay machine to shut down.

Internally, this is accomplished by immediately freeing the heap-allocated
`circuit_t.padding_info` field corresponding to that machine, but still preserving the
`circuit_t.padding_machine` pointer to the global padding machine
specification until the response comes back from the relay. Once the response
comes back, that `circuit_t.padding_machine` pointer is set to NULL, if the
response machine number matches the current machine present.

Because of this partial shutdown condition, we have two macros for iterating
over machines. `FOR_EACH_ACTIVE_CIRCUIT_MACHINE_BEGIN()` is used to iterate
over machines that have both a `circuit_t.padding_info` slot and a
`circuit_t.padding_machine` slot occupied. `FOR_EACH_CIRCUIT_MACHINE_BEGIN()`
is used when we need to iterate over all machines that are either active or
are simply waiting for a response to a shutdown request.

If the machine is replaced instead of just shut down, then the client frees
the `circuit_t.padding_info`, and then sets the `circuit_t.padding_machine`
and `circuit_t.padding_info` fields for this next machine immediately. This is
done in `circpad_add_matching_machines()`. In this case, since the new machine
should have a different machine number, the shut down response from the relay
is silently discarded, since it will not match the new machine number.

If this sequence of machine teardown and spin-up happens rapidly enough for
the same machine number (as opposed to different machines), then a race
condition can happen. This is
[known bug #30992](https://bugs.torproject.org/30992).

When the relay side decides to shut down a machine, it sends a
`RELAY_COMMAND_PADDING_NEGOTIATED` towards the client. If this cell matches the
current machine number on the client, that machine is torn down, by freeing
the `circuit_t.padding_info` slot and immediately setting
`circuit_t.padding_machine` slot to NULL.

Additionally, if Tor decides to close a circuit forcibly due to error before
the padding machine is shut down, then `circuit_t.padding_info` is still
properly freed by the call to `circpad_circuit_free_all_machineinfos()`
in `circuit_free_()`.

### 6.2. Machine Application Events

The framework checks client-side origin circuits to see if padding machines
should be activated or terminated during specific event callbacks in
`circuitpadding.c`. We list these event callbacks here only for reference. You
should not modify any of these callbacks to get your machine to run; instead,
you should use the `circpad_machine_spec_t.conditions` field.

However, you may add new event callbacks if you need other activation events,
for example to provide obfuscation-layer or application-layer signaling. Any
new event callbacks should behave exactly like the existing callbacks.

During each of these event callbacks, the framework checks to see if any
current running padding machines have conditions that no longer apply as a
result of the event, and shuts those machines down. Then, it checks to see if
any new padding machines should be activated as a result of the event, based
on their circuit application conditions. **Remember: Machines are checked in
reverse order in the machine list. This means that later, more recently added
machines take precedence over older, earlier entries in each list.**

Both of these checks are performed using the machine application conditions
that you specify in your machine's `circpad_machine_spec_t.conditions` field.

The machine application event callbacks are prefixed by `circpad_machine_event_` by convention in circuitpadding.c. As of this writing, these callbacks are:

  - `circpad_machine_event_circ_added_hop()`: Called whenever a new hop is
    added to a circuit.
  - `circpad_machine_event_circ_built()`: Called when a circuit has completed
    construction and is
    opened. <!-- open != ready for traffic. Which do we mean? -nickm -->
  - `circpad_machine_event_circ_purpose_changed()`: Called when a circuit
    changes purpose.
  - `circpad_machine_event_circ_has_no_relay_early()`: Called when a circuit
    runs out of `RELAY_EARLY` cells.
  - `circpad_machine_event_circ_has_streams()`: Called when a circuit gets a
    stream attached.
  - `circpad_machine_event_circ_has_no_streams()`: Called when the last
    stream is detached from a circuit.

### 6.3. Internal Machine Events

To provide for some additional capabilities beyond simple finite state machine
behavior, the circuit padding machines also have internal events that they
emit to themselves when packet count length limits are hit, when the Infinity
bin is sampled, and when the histogram bins are emptied of all tokens.

These events are implemented as `circpad_internal_event_*` functions in
`circuitpadding.c`, which are called from various areas that determine when
the events should occur.

While the conditions that trigger these internal events to be called may be
complex, they are processed by the state machine definitions in a nearly
identical manner as the cell processing events, with the exception that they
are sent to the current machine only, rather than all machines on the circuit.


## 7. Future Features and Optimizations

While implementing the circuit padding framework, our goal was to deploy a
system that obscured client-side onion service circuit setup and supported
deployment of WTF-PAD and/or APE. Along the way, we noticed several features
that might prove useful to others, but were not essential to implement
immediately. We do not have immediate plans to implement these ideas, but we
would gladly accept patches that do so.

The following list gives an overview of these improvements, but as this
document ages, it may become stale. The canonical list of improvements that
researchers may find useful is labeled in our bugtracker with
[Padding Research](https://gitlab.torproject.org/tpo/core/tor/-/issues?scope=all&utf8=%E2%9C%93&state=opened&label_name[]=Padding%20Research),
and the list of improvements that are known to be necessary for some research
areas are labeled with
[Padding Research Requires](https://gitlab.torproject.org/tpo/core/tor/-/issues?scope=all&utf8=%E2%9C%93&state=opened&label_name[]=Padding%20Research%20Requires).

Please consult those lists for the latest status of these issues. Note that
not all fixes will be backported to all Tor versions, so be mindful of which
Tor releases receive which fixes as you conduct your experiments.

### 7.1. Load Balancing and Flow Control

Fortunately, non-Exit bandwidth is already plentiful and exceeds the Exit
capacity, and we anticipate that if we inform our relay operator community of
the need for non-Exit bandwidth to satisfy padding overhead requirements,
they will be able to provide that with relative ease.

Unfortunately, padding machines that have large quantities of overhead will
require changes to our load balancing system to account for this
overhead. The necessary changes are documented in
[Proposal 265](https://gitweb.torproject.org/torspec.git/tree/proposals/265-load-balancing-with-overhead.txt).

Additionally, padding cells are not currently subjected to flow control. For
high amounts of padding, we may want to change this. See [ticket
31782](https://bugs.torproject.org/31782) for details.

### 7.2. Timing and Queuing Optimizations

The circuitpadding framework has some timing related issues that may impact
results. If high-resolution timestamps are fed to opaque deep learning
trainers, those training models may end up able to differentiate padding
traffic from non-padding traffic due to these timing bugs.

The circuit padding cell event callbacks come from post-decryption points in
the cell processing codepath, and from the pre-queue points in the cell send
codepath. This means that our cell events will not reflect the actual time
when packets are read or sent on the wire. This is much worse in the send
direction, as the circuitmux queue, channel outbuf, and kernel TCP buffer will
impose significant additional delay between when we currently report that a
packet was sent, and when it actually hits the wire.

[Ticket 29494](https://bugs.torproject.org/29494) has a more detailed
description of this problem, and an experimental branch that changes the cell
event callback locations to be from circuitmux post-queue, which with KIST,
should be an accurate reflection of when they are actually sent on the wire.

If your padding machine and problem space depends on very accurate notions of
relay-side packet timing, please try that branch and let us know on the
ticket if you need any further assistance fixing it up.

Additionally, with these changes, it will be possible to provide further
overhead reducing optimizations by letting machines specify flags to indicate
that padding should not be sent if there are any cells pending in the cell
queue, for doing things like extending cell bursts more accurately and with
less overhead.

However, even if we solve the queuing issues, Tor's current timers are not as
precise as some padding designs may require. We will still have issues of
timing precision to solve. [Ticket 31653](https://bugs.torproject.org/31653)
describes an issue the circuit padding system has with sending 0-delay padding
cells, and [ticket 32670](https://bugs.torproject.org/32670) describes a
libevent timer accuracy issue, which causes callbacks to vary up to 10ms from
their scheduled time, even in absence of load.

All of these issues strongly suggest that you either truncate the resolution
of any timers you feed to your classifier, or that you omit timestamps
entirely from the classification problem until these issues are addressed.

### 7.3. Better Machine Negotiation

Circuit padding is applied to circuits through machine conditions.

The following machine conditions may be useful for some use cases, but have
not been implemented yet:
  * [Exit Policy-based Stream Conditions](https://bugs.torproject.org/29083)
  * [Probability to apply machine/Cointoss condition](https://bugs.torproject.org/30092)
  * [Probability distributions for launching new padding circuit(s)](https://bugs.torproject.org/31783)
  * [More flexible purpose handling](https://bugs.torproject.org/32040)

Additionally, the following features may help to obscure that padding is being
negotiated, and/or streamline that negotiation process:
  * [Always send negotiation cell on all circuits](https://bugs.torproject.org/30172)
  * [Better shutdown handling](https://bugs.torproject.org/30992)
  * [Preference-ordered negotiation menu](https://bugs.torproject.org/30348)

### 7.4. Probabilistic State Transitions

Right now, the state machine transitions are fully deterministic. However,
one could imagine a state machine that uses probabilistic transitions between
states to simulate a random walk or Hidden Markov Model traversal across
several pages.

The simplest way to implement this is to make  the `circpad_state_t.next_state` array
into an array of structs that have a next state field, and a probability to
transition to that state.

If you need this feature, please see [ticket
31787](https://bugs.torproject.org/31787) for more details.

### 7.5. More Complex Pattern Recognition

State machines are extremely efficient sequence recognition devices. But they
are not great pattern recognition devices. This is one of the reasons why
[Adaptive Padding](https://www.freehaven.net/anonbib/cache/ShWa-Timing06.pdf)
used state machines in combination with histograms, to model the target
distribution of interpacket delays for transmitted packets.

However, there currently is no such optimization for reaction to patterns of
*received* traffic. There may also be cases where defenses must react to more
complex patterns of sent traffic than can be expressed by our current
histogram and length count events.

For example: if you wish your machine to react to a certain count of incoming
cells in a row, right now you have to have a state for each cell, and use the
infinity bin to timeout of the sequence in each state. We could make this more
compact if each state had an arrival cell counter and inter-cell timeout. Or
we could make more complex mechanisms to recognize certain patterns of arrival
traffic in a state.

The best way to build recognition primitives like this into the framework is
to add additional [Internal Machine Events](#63-internal-machine-events) for
the pattern in question.

As another simple example, a useful additional event might be to transition
whenever any of your histogram bins are empty, rather than all of them. To do
this, you would add `CIRCPAD_EVENT_ANY_BIN_EMPTY` to the enum
`circpad_event_t` in `circuitpadding.h`. You would then create a function
`circuitpadding_internal_event_any_bin_empty()`, which would work just like
`circuitpadding_internal_event_bin_empty()`, and also be called from
`check_machine_token_supply()` in `circuitpadding.c` but with the check for
each bin being zero instead of the total. With this change, new machines could
react to this new event in the same way as any other.

If you have any other ideas that may be useful, please comment on [ticket
32680](https://bugs.torproject.org/32680).


## 8. Open Research Problems

### 8.1. Onion Service Circuit Setup

Our circuit setup padding does not address timing-based features, only
packet counts. Deep learning can probably see this.

However, before going too deep down the timing rabithole, we may need to make
[some improvements to Tor](#72-timing-and-queuing-optimizations). Please
comment on those tickets if you need this.

### 8.2. Onion Service Fingerprinting

We have done nothing to obscure the service side of onion service circuit
setup. Because service-side onion services will have the reverse traffic byte
counts as normal clients, they will likely need some kind of [hybrid
application layer traffic shaping](#53-sketch-of-tamaraw), in addition to
simple circuit setup obfuscation.

Fingerprinting in
[combination](https://github.com/mikeperry-tor/vanguards/blob/master/README_SECURITY.md)
with
[vanguards](https://github.com/mikeperry-tor/vanguards/blob/master/README_TECHNICAL.md)
ia also an open issue.

### 8.3. Open World Fingerprinting

Similarly, Open World/clearweb website fingerprinting defenses remain
an unsolved problem from the practicality point of view. The original WTF-PAD
defense was never tuned, and it is showing accuracy issues against deep
learning attacks.

### 8.4. Protocol Usage Fingerprinting

Traffic Fingerprinting to determine the protocol in use by a client has not
been studied, either from the attack or defense point of view.

### 8.5. Datagram Transport Side Channels

Padding can reduce the accuracy of dropped-cell side channels in such
transports, but we don't know [how to measure
this](https://lists.torproject.org/pipermail/tor-dev/2018-November/013562.html).

## 9. Must Read Papers

These are by far the most important papers in the space, to date:

 - [Tamaraw](https://www.cypherpunks.ca/~iang/pubs/webfingerprint-ccs14.pdf)
 - [Bayes, Not Naive](https://www.petsymposium.org/2017/papers/issue4/paper50-2017-4-source.pdf)
 - [Anonymity Trilemma](https://eprint.iacr.org/2017/954.pdf)
 - [WTF-PAD](http://arxiv.org/pdf/1512.00524)

Except for WTF-PAD, these papers were selected because they point towards
optimality bounds that can be benchmarked against.

We cite them even though we are skeptical that provably optimal defenses can
be constructed, at least not without trivial or impractical transforms (such as
those that can be created with unbounded queue capacity, or stored knowledge
of traces for every possible HTTP trace on the Internet).

We also are not demanding an optimality or security proof for every defense.

Instead, we cite the above as benchmarks. We believe the space, especially the
open-world case, to be more akin to an optimization problem, where a
WTF-PAD-like defense must be tuned through an optimizer to produce results
comparable to provably optimal but practically unrealizable defenses, through
rigorous adversarial evaluation.

## A. Acknowledgments

This research was supported in part by NSF grants CNS-1619454 and CNS-1526306.
