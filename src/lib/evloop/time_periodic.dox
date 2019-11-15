
@page time_periodic Time and periodic events in Tor

### What time is it? ###

We have several notions of the current time in Tor.

The *wallclock time* is available from time(NULL) with
second-granularity and tor_gettimeofday() with microsecond
granularity.  It corresponds most closely to "the current time and date".

The *monotonic time* is available with the set of monotime_\*
functions declared in compat_time.h.  Unlike the wallclock time, it
can only move forward. It does not necessarily correspond to a real
world time, and it is not portable between systems.

The *coarse monotonic time* is available from the set of
monotime_coarse_\* functions in compat_time.h. It is the same as
monotime_\* on some platforms. On others, it gives a monotonic timer
with less precision, but which it's more efficient to access.

### Cached views of time. ###

On some systems (like Linux), many time functions use a VDSO to avoid
the overhead of a system call.  But on other systems, gettimeofday()
and time() can be costly enough that you wouldn't want to call them
tens of thousands of times.  To get a recent, but not especially
accurate, view of the current time, see approx_time() and
tor_gettimeofday_cached().


### Parsing and encoding time values ###

Tor has functions to parse and format time in these formats:

 - RFC1123 format. ("Fri, 29 Sep 2006 15:54:20 GMT").  For this,
   use format_rfc1123_time() and parse_rfc1123_time.

 - ISO8601 format. ("2006-10-29 10:57:20") For this, use
   format_local_iso_time() and format_iso_time().  We also support the
   variant format "2006-10-29T10:57:20" with format_iso_time_nospace(), and
   "2006-10-29T10:57:20.123456" with format_iso_time_nospace_usec().

 - HTTP format collections (preferably "Mon, 25 Jul 2016 04:01:11
   GMT" or possibly "Wed Jun 30 21:49:08 1993" or even "25-Jul-16
   04:01:11 GMT"). For this, use parse_http_time().  Don't generate anything
   but the first format.

Some of these functions use struct tm. You can use the standard
tor_localtime_r() and tor_gmtime_r() to wrap these in a safe way. We
also have a tor_timegm() function.

### Scheduling events ###

The main way to schedule a not-too-frequent periodic event with
respect to the Tor mainloop is via the mechanism in periodic.c.
There's a big table of periodic_events in mainloop.c, each of which gets
invoked on its own schedule.  You should not expect more than about
one second of accuracy with these timers.

You can create an independent timer using libevent directly, or using
the periodic_timer_new() function.  But you should avoid doing this
for per-connection or per-circuit timers: Libevent's internal timer
implementation uses a min-heap, and those tend to start scaling poorly
once you have a few thousand entries.

If you need to create a large number of fine-grained timers for some
purpose, you should consider the mechanism in src/common/timers.c,
which is optimized for the case where you have a large number of
timers with not-too-long duration, many of which will be deleted
before they actually expire. These timers should be reasonably
accurate within a handful of milliseconds -- possibly better on some
platforms.  (The timers.c module uses William Ahern's timeout.c
implementation as its backend, which is based on a hierarchical timing
wheel algorithm. It's cool stuff; check it out.)

