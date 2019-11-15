
@page strings String processing in Tor

Since you're reading about a C program, you probably expected this
section: it's full of functions for manipulating the (notoriously
dubious) C string abstraction.  I'll describe some often-missed
highlights here.

### Comparing strings and memory chunks ###

We provide strcmpstart() and strcmpend() to perform a strcmp with the start
or end of a string.

	tor_assert(!strcmpstart("Hello world","Hello"));
	tor_assert(!strcmpend("Hello world","world"));

	tor_assert(!strcasecmpstart("HELLO WORLD","Hello"));
	tor_assert(!strcasecmpend("HELLO WORLD","world"));

To compare two string pointers, either of which might be NULL, use
strcmp_opt().

To search for a string or a chunk of memory within a non-null
terminated memory block, use tor_memstr or tor_memmem respectively.

We avoid using memcmp() directly, since it tends to be used in cases
when having a constant-time operation would be better.  Instead, we
recommend tor_memeq() and tor_memneq() for when you need a
constant-time operation.  In cases when you need a fast comparison,
and timing leaks are not a danger, you can use fast_memeq() and
fast_memneq().

It's a common pattern to take a string representing one or more lines
of text, and search within it for some other string, at the start of a
line.  You could search for "\\ntarget", but that would miss the first
line.  Instead, use find_str_at_start_of_line.

### Parsing text ###

Over the years, we have accumulated lots of ways to parse text --
probably too many. Refactoring them to be safer and saner could be a
good project!  The one that seems most error-resistant is tokenizing
text with smartlist_split_strings().  This function takes a smartlist,
a string, and a separator, and splits the string along occurrences of
the separator, adding new strings for the sub-elements to the given
smartlist.

To handle time, you can use one of the functions mentioned above in
"Parsing and encoding time values".

For numbers in general, use the tor_parse_{long,ulong,double,uint64}
family of functions.  Each of these can be called in a few ways.  The
most general is as follows:

      const int BASE = 10;
      const int MINVAL = 10, MAXVAL = 10000;
      const char *next;
      int ok;
      long lng = tor_parse_long("100", BASE, MINVAL, MAXVAL, &ok, &next);

The return value should be ignored if "ok" is set to false.  The input
string needs to contain an entire number, or it's considered
invalid... unless the "next" pointer is available, in which case extra
characters at the end are allowed, and "next" is set to point to the
first such character.

### Generating blocks of text ###

For not-too-large blocks of text, we provide tor_asprintf(), which
behaves like other members of the sprintf() family, except that it
always allocates enough memory on the heap for its output.

For larger blocks: Rather than using strlcat and strlcpy to build
text, or keeping pointers to the interior of a memory block, we
recommend that you use the smartlist_* functions to build a smartlist
full of substrings in order.  Then you can concatenate them into a
single string with smartlist_join_strings(), which also takes optional
separator and terminator arguments.

Alternatively, you might find it more convenient (and more
allocation-efficient) to use the buffer API in buffers.c: Construct a buf_t
object, add your data to it with buf_add_string(), buf_add_printf(), and so
on, then call buf_extract() to get the resulting output.

As a convenience, we provide smartlist_add_asprintf(), which combines
the two methods above together.  Many of the cryptographic digest
functions also accept a not-yet-concatenated smartlist of strings.

### Logging helpers ###

Often we'd like to log a value that comes from an untrusted source.
To do this, use escaped() to escape the nonprintable characters and
other confusing elements in a string, and surround it by quotes.  (Use
esc_for_log() if you need to allocate a new string.)

It's also handy to put memory chunks into hexadecimal before logging;
you can use hex_str(memory, length) for that.

The escaped() and hex_str() functions both provide outputs that are
only valid till they are next invoked; they are not threadsafe.

*/
