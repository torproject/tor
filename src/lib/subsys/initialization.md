
@page initialization Initialization and shutdown

@tableofcontents

@section overview Overview

Tor has a single entry point: tor_run_main() in main.c.  All the ways of
starting a Tor process (ntmain.c, tor_main.c, and tor_api.c) work by invoking tor_run_main().

The tor_run_main() function normally exits (@ref init_exceptwhen "1") by
returning: not by calling abort() or exit().  Before it returns, it calls
tor_cleanup() in shutdown.c.

Conceptually, there are several stages in running Tor.

1. First, we initialize those modules that do not depend on the
   configuration.  This happens in the first half of tor_run_main(), and the
   first half of tor_init().  (@ref init_pending_refactor "2")

2. Second, we parse the command line and our configuration, and configure
   systems that depend on our configuration or state.  This configuration
   happens midway through tor_init(), which invokes
   options_init_from_torrc().  We then initialize more systems from the
   second half of tor_init().

3. At this point we may exit early if we have been asked to do something
   requiring no further initialization, like printing our version number or
   creating a new signing key.  Otherwise, we proceed to run_tor_main_loop(),
   which initializes some network-specific parts of Tor, grabs some
   daemon-only resources (like the data directory lock) and starts Tor itself
   running.


> @anchor init_exceptwhen 1. tor_run_main() _can_ terminate with a call to
> abort() or exit(), but only when crashing due to a bug, or when forking to
> run as a daemon.

> @anchor init_pending_refactor 2. The pieces of code that I'm describing as
> "the first part of tor_init()" and so on deserve to be functions with their
> own name.  I'd like to refactor them, but before I do so, there is some
> slight reorganization that needs to happen.  Notably, the
> nt_service_parse_options() call ought logically to be later in our
> initialization sequence.  See @ticket{32447} for our refactoring progress.


@section subsys Subsystems and initialization

Our current convention is to use the subsystem mechanism to initialize and
clean up pieces of Tor.  The more recently updated pieces of Tor will use
this mechanism.  For examples, see e.g. time_sys.c or log_sys.c.

In simplest terms, a **subsystem** is a logically separate part of Tor that
can be initialized, shut down, managed, and configured somewhat independently
of the rest of the program.

The subsys_fns_t type describes a subsystem and a set of functions that
initialize it, desconstruct it, and so on. To define a subsystem, we declare
a `const` instance of subsys_fns_t.  See the documentation for subsys_fns_t
for a full list of these functions.

After defining a subsystem, it must be inserted in subsystem_list.c.  At that
point, table-driven mechanisms in subsysmgr.c will invoke its functions when
appropriate.

@subsection vsconfig Initialization versus configuration

We note that the initialization phase of Tor occurs before any configuration
is read from disk -- and therefore before any other files are read from
disk.  Therefore, any behavior that depends on Tor's configuration or state
must occur _after_ the initialization process, during configuration.




