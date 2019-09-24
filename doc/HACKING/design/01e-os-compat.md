
## OS compatibility functions ##

We've got a bunch of functions to wrap differences between various
operating systems where we run.

### The filesystem ###

We wrap the most important filesystem functions with load-file,
save-file, and map-file abstractions declared in util.c or compat.c.  If
you're messing about with file descriptors yourself, you might be doing
things wrong.  Most of the time, write_str_to_file() and
read_str_from_file() are all you need.

Use the check_private_directory() function to create or verify the
presence of directories, and tor_listdir() to list the files in a
directory.

Those modules also have functions for manipulating paths a bit.

### Networking ###

Nearly all the world is on a Berkeley sockets API, except for
windows, whose version of the Berkeley API was corrupted by late-90s
insistence on backward compatibility with the
sort-of-berkeley-sort-of-not add-on *thing* that was WinSocks.

What's more, everybody who implemented sockets realized that select()
wasn't a very good way to do nonblocking IO... and then the various
implementations all decided to so something different.

You can forget about most of these differences, fortunately: We use
libevent to hide most of the differences between the various networking
backends, and we add a few of our own functions to hide the differences
that Libevent doesn't.

To create a network connection, the right level of abstraction to look
at is probably the connection_t system in connection.c.  Most of the
lower level work has already been done for you.  If you need to
instantiate something that doesn't fit well with connection_t, you
should see whether you can instantiate it with connection_t anyway -- or
you might need to refactor connection.c a little.

Whenever possible, represent network addresses as tor_addr_t.

### Process launch and monitoring ###

Launching and/or monitoring a process is tricky business. You can use
the mechanisms in procmon.c and tor_spawn_background(), but they're both
a bit wonky.  A refactoring would not be out of order.
