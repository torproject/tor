@dir /lib
@brief lib: low-level functionality.

The "lib" directory contains low-level functionality.  In general, this
code is not necessarily Tor-specific, but is instead possibly useful for
other applications.

The modules in `lib` are currently well-factored: each one depends
only on lower-level modules.  You can see an up-to-date list of the
modules, sorted from lowest to highest level, by running
`./scripts/maint/practracker/includes.py --toposort`.

As of this writing, the library modules are (from lowest to highest
level):

   - \refdir{lib/cc} -- Macros for managing the C compiler and
     language.

   - \refdir{lib/version} -- Holds the current version of Tor.

   - \refdir{lib/testsupport} -- Helpers for making
     test-only code, and test mocking support.

   - \refdir{lib/defs} -- Lowest-level constants.

   - \refdir{lib/subsys} -- Types used for declaring a
     "subsystem". (_A subsystem is a module with support for initialization,
     shutdown, configuration, and so on._)

   - \refdir{lib/conf} -- For declaring configuration options.

   - \refdir{lib/arch} -- For handling differences in CPU
     architecture.

   - \refdir{lib/err} -- Lowest-level error handling code.

   - \refdir{lib/malloc} -- Memory management.
     management.

   - \refdir{lib/intmath} -- Integer mathematics.

   - \refdir{lib/fdio} -- For
      reading and writing n file descriptors.

   - \refdir{lib/lock} -- Simple locking support.
      (_Lower-level than the rest of the threading code._)

   - \refdir{lib/ctime} -- Constant-time code to avoid
     side-channels.

   - \refdir{lib/string} -- Low-level string manipulation.

   - \refdir{lib/wallclock} --
     For inspecting and manipulating the current (UTC) time.

   - \refdir{lib/osinfo} -- For inspecting the OS version
     and capabilities.

   - \refdir{lib/smartlist_core} -- The bare-bones
     pieces of our dynamic array ("smartlist") implementation.

   - \refdir{lib/log} -- Log messages to files, syslogs, etc.

   - \refdir{lib/container} -- General purpose containers,
     including dynamic arrays ("smartlists"), hashtables, bit arrays,
     etc.

   - \refdir{lib/trace} -- A general-purpose API
     function-tracing functionality Tor.  (_Currently not much used._)

   - \refdir{lib/thread} -- Mid-level Threading.

   - \refdir{lib/term} -- Terminal manipulation
     (like reading a password from the user).

   - \refdir{lib/memarea} -- A fast
     "arena" style allocator, where the data is freed all at once.

   - \refdir{lib/encoding} -- Encoding
     data in various formats, datatypes, and transformations.

   - \refdir{lib/dispatch} -- A general-purpose in-process
     message delivery system.

   - \refdir{lib/sandbox} -- Our Linux seccomp2 sandbox
     implementation.

   - \refdir{lib/pubsub} -- A publish/subscribe message passing system.

   - \refdir{lib/fs} -- Files, filenames, directories, etc.

   - \refdir{lib/confmgt} -- Parse, encode, and manipulate onfiguration files.

   - \refdir{lib/crypt_ops} -- Cryptographic operations.

   - \refdir{lib/meminfo} -- Functions for inspecting our
     memory usage, if the malloc implementation exposes that to us.

   - \refdir{lib/time} -- Higher level time functions, including
     fine-gained and monotonic timers.

   - \refdir{lib/math} -- Floating-point mathematical utilities.

   - \refdir{lib/buf} -- An efficient byte queue.

   - \refdir{lib/net} -- Networking code, including address
     manipulation, compatibility wrappers, etc.

   - \refdir{lib/compress} -- Wraps several compression libraries.

   - \refdir{lib/geoip} -- IP-to-country mapping.

   - \refdir{lib/tls} -- TLS library wrappers.

   - \refdir{lib/evloop} -- Low-level event-loop.

   - \refdir{lib/process} -- Launch and manage subprocesses.

### What belongs in lib?

In general, if you can imagine some program wanting the functionality
you're writing, even if that program had nothing to do with Tor, your
functionality belongs in lib.

If it falls into one of the existing "lib" categories, your
functionality belongs in lib.

If you are using platform-specific `ifdef`s to manage compatibility
issues among platforms, you should probably consider whether you can
put your code into lib.

