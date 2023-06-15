# A Padding Machine from Scratch

A quickstart guide by Tobias Pulls.

This document describes the process of building a "padding machine" in tor's new
circuit padding framework from scratch. Notes were taken as part of porting
[Adaptive Padding Early
(APE)](https://www.cs.kau.se/pulls/hot/thebasketcase-ape/) from basket2 to the
circuit padding framework. The goal is just to document the process and provide
useful pointers along the way, not create a useful machine.

The quick and dirty plan is to:
1. clone and compile tor
2. use newly built tor in TB and at small (non-exit) relay we run
3. add a bare-bones APE padding machine
4. run the machine, inspect logs for activity
5. port APE's state machine without thinking much about parameters

## Clone and compile tor

```console
$ git clone https://gitlab.torproject.org/tpo/core/tor.git
$ cd tor
$ git checkout tor-0.4.1.5
```
Above we use the tag for tor-0.4.1.5 where the circuit padding framework was
released. Note that this version of the framework is missing many features and
fixes that have since been merged to origin/master. If you need the newest
framework features, you should use that master instead.

```console
$ sh autogen.sh
$ ./configure
$ make
```
When you run `./configure` you'll be told of missing dependencies and packages
to install on debian-based distributions. Important: if you plan to run `tor` on
a relay as part of the real Tor network and your server runs a distribution that
uses systemd, then I'd recommend that you `apt install dpkg dpkg-dev
libevent-dev libssl-dev asciidoc quilt dh-apparmor libseccomp-dev dh-systemd
libsystemd-dev pkg-config dh-autoreconf libfakeroot zlib1g zlib1g-dev automake
liblzma-dev libzstd-dev` and ensure that tor has systemd support enabled:
`./configure --enable-systemd`. Without this, on a recent Ubuntu, my tor service
was forcefully restarted (SIGINT interrupt) by systemd every five minutes.

If you want to install on your localsystem, run `make install`. For our case we
just want the tor binary at `src/app/tor`.

## Use tor in TB and at a relay

Download and install a fresh Tor Browser (TB) from torproject.org. Make sure it
works. From the command line, relative to the folder created when you extracted
TB, run `./Browser/start-tor-browser --verbose` to get some basic log output.
Note the version of tor, in my case, `Tor 0.4.0.5 (git-bf071e34aa26e096)` as
part of TB 8.5.4. Shut down TB, copy the `tor` binary that you compiled earlier
and replace `Browser/TorBrowser/Tor/tor`. Start TB from the command line again,
you should see a different version, in my case `Tor 0.4.1.5
(git-439ca48989ece545)`.

The relay we run is also on linux, and `tor` is located at `/usr/bin/tor`. To
view relevant logs since last boot `sudo journalctl -b /usr/bin/tor`, where we
find `Tor 0.4.0.5 running on Linux`. Copy the locally compiled `tor` to the
relay at a temporary location and then make sure it's ownership and access
rights are identical to `/usr/bin/tor`. Next, shut down the running tor service
with `sudo service tor stop`, wait for it to stop (typically 30s), copy our
locally compiled tor to replace `/usr/bin/tor` then start the service again.
Checking the logs we see `or 0.4.1.5 (git-439ca48989ece545)`.

Repeatedly shutting down a relay is detrimental to the network and should be
avoided. Sorry about that.

We have one more step left before we move on the machine: configure TB to always
use our middle relay. Edit `Browser/TorBrowser/Data/Tor/torrc` and set
`MiddleNodes <fingerprint>`, where `<fingerprint>` is the fingerprint of the
relay. Start TB, visit a website, and manually confirm that the middle is used
by looking at the circuit display.

## Add a bare-bones APE padding machine

Now the fun part. We have several resources at our disposal (mind that links
might be broken in the future, just search for the headings):
- The official [Circuit Padding Developer
  Documentation](https://storm.torproject.org/shared/ChieH_sLU93313A2gopZYT3x2waJ41hz5Hn2uG1Uuh7).
- Notes we made on the [implementation of the circuit padding
  framework](https://github.com/pylls/padding-machines-for-tor/blob/master/notes/circuit-padding-framework.md).
- The implementation of the current circuit padding machines in tor:
  [circuitpadding.c](https://gitweb.torproject.org/tor.git/tree/src/core/or/circuitpadding_machines.c)
  and
  [circuitpadding_machines.h](https://gitweb.torproject.org/tor.git/tree/src/core/or/circuitpadding_machines.h).

Please consult the above links for details. Moving forward, the focus is to
describe what was done, not necessarily explaining all the details why.

Since we plan to make changes to tor, create a new branch `git checkout -b
circuit-padding-ape-machine tor-0.4.1.5`.

We start with declaring two functions, one for the machine at the client and one
at the relay, in `circuitpadding_machines.h`:

```c
void circpad_machine_relay_wf_ape(smartlist_t *machines_sl);
void circpad_machine_client_wf_ape(smartlist_t *machines_sl);
```

The definitions go into `circuitpadding_machines.c`:

```c
/**************** Adaptive Padding Early (APE) machine ****************/

/**
 * Create a relay-side padding machine based on the APE design.
 */
void
circpad_machine_relay_wf_ape(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *relay_machine
  = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  relay_machine->name = "relay_wf_ape";
  relay_machine->is_origin_side = 0; // relay-side

  // Pad to/from the middle relay, only when the circuit has streams
  relay_machine->target_hopnum = 2;
  relay_machine->conditions.min_hops = 2;
  relay_machine->conditions.state_mask = CIRCPAD_CIRC_STREAMS;

  // limits to help guard against excessive padding
  relay_machine->allowed_padding_count = 1;
  relay_machine->max_padding_percent = 1;

  // one state to start with: START (-> END, never takes a slot in states)
  circpad_machine_states_init(relay_machine, 1);
  relay_machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_END;

  // register the machine
  relay_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(relay_machine, machines_sl);

  log_info(LD_CIRC,
           "Registered relay WF APE padding machine (%u)",
           relay_machine->machine_num);
}

/**
 * Create a client-side padding machine based on the APE design.
 */
void
circpad_machine_client_wf_ape(smartlist_t *machines_sl)
{
    circpad_machine_spec_t *client_machine
  = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  client_machine->name = "client_wf_ape";
  client_machine->is_origin_side = 1; // client-side

  /** Pad to/from the middle relay, only when the circuit has streams, and only
  * for general purpose circuits (typical for web browsing)
  */
  client_machine->target_hopnum = 2;
  client_machine->conditions.min_hops = 2;
  client_machine->conditions.state_mask = CIRCPAD_CIRC_STREAMS;
  client_machine->conditions.purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_GENERAL);

  // limits to help guard against excessive padding
  client_machine->allowed_padding_count = 1;
  client_machine->max_padding_percent = 1;

  // one state to start with: START (-> END, never takes a slot in states)
  circpad_machine_states_init(client_machine, 1);
  client_machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_END;

  client_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(client_machine, machines_sl);
  log_info(LD_CIRC,
           "Registered client WF APE padding machine (%u)",
           client_machine->machine_num);
}
```

We also have to modify `circpad_machines_init()` in `circuitpadding.c` to
register our machines:

```c
/* Register machines for the APE WF defense */
circpad_machine_client_wf_ape(origin_padding_machines);
circpad_machine_relay_wf_ape(relay_padding_machines);
```

We run `make` to get a new `tor` binary and copy it to our local TB.

## Run the machine

To be able
to view circuit info events in the console as we launch TB, we add `Log
[circ]info notice stdout` to `torrc` of TB.

Running TB to visit example.com we first find in the log:

```
Aug 30 18:36:43.000 [info] circpad_machine_client_hide_intro_circuits(): Registered client intro point hiding padding machine (0)
Aug 30 18:36:43.000 [info] circpad_machine_relay_hide_intro_circuits(): Registered relay intro circuit hiding padding machine (0)
Aug 30 18:36:43.000 [info] circpad_machine_client_hide_rend_circuits(): Registered client rendezvous circuit hiding padding machine (1)
Aug 30 18:36:43.000 [info] circpad_machine_relay_hide_rend_circuits(): Registered relay rendezvous circuit hiding padding machine (1)
Aug 30 18:36:43.000 [info] circpad_machine_client_wf_ape(): Registered client WF APE padding machine (2)
Aug 30 18:36:43.000 [info] circpad_machine_relay_wf_ape(): Registered relay WF APE padding machine (2)
```

All good, our machine is running. Looking further we find:

```
Aug 30 18:36:55.000 [info] circpad_setup_machine_on_circ(): Registering machine client_wf_ape to origin circ 2 (5)
Aug 30 18:36:55.000 [info] circpad_node_supports_padding(): Checking padding: supported
Aug 30 18:36:55.000 [info] circpad_negotiate_padding(): Negotiating padding on circuit 2 (5), command 2
Aug 30 18:36:55.000 [info] circpad_machine_spec_transition(): Circuit 2 circpad machine 0 transitioning from 0 to 65535
Aug 30 18:36:55.000 [info] circpad_machine_spec_transitioned_to_end(): Padding machine in end state on circuit 2 (5)
Aug 30 18:36:55.000 [info] circpad_circuit_machineinfo_free_idx(): Freeing padding info idx 0 on circuit 2 (5)
Aug 30 18:36:55.000 [info] circpad_handle_padding_negotiated(): Middle node did not accept our padding request on circuit 2 (5)
```
We see that our middle support padding (since we upgraded to tor-0.4.1.5), that
we attempt to negotiate, our machine starts on the client, transitions to the
end state, and is freed. The last line shows that the middle doesn't have a
padding machine that can run.

Next, we follow the same steps as earlier and replace the modified `tor` at our
middle relay. We don't update the logging there to avoid logging on the info
level on the live network. Looking at the client log again we see that
negotiation works as before except for the last line: it's missing, so the
machine is running at the middle as well.

## Implementing the APE state machine

Porting is fairly straightforward: define the states for all machines, add two
more machines (for the receive portion of WTFP-PAD, beyond AP), and pick
reasonable parameters for the distributions (I completely winged it now, as when
implementing APE). The [circuit-padding-ape-machine
branch](https://github.com/pylls/tor/tree/circuit-padding-ape-machine) contains
the commits for the full machines with plenty of comments.

Some comments on the process:

- `tor-0.4.1.5` did not support two machines on the same circuit, the following
  fix had to be made: https://bugs.torproject.org/tpo/core/tor/31111 .
  The good news is that everything else seems to work after the small change in
  the fix.
- APE randomizes its distributions. Currently, this can only be done during
  start of `tor`. This makes sense in the censorship circumvention setting
  (`obfs4`), less so for WF defenses: further randomizing each circuit is likely
  a PITA for attackers with few downsides.
- it was annoying to figure out that the lack of systemd support in my compiled
  tor caused systemd to interrupt (SIGINT) my tor process at the middle relay
  every five minutes. Updated build steps above to hopefully save others the
  pain.
- there's for sure some bug on relays when sending padding cells too early (?).
  It can happen with some probability with the APE implementation due to
  `circpad_machine_relay_wf_ape_send()`. Will investigate next.
- Moving the registration of machines from the definition of the machines to
  `circpad_machines_init()` makes sense, as suggested in the circuit padding doc
  draft.

Remember that APE is just a proof-of-concept and we make zero claims about its
ability to withstand WF attacks, in particular those based on deep learning.
