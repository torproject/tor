@dir /lib/log
@brief lib/log: Log messages to files, syslogs, etc.

You can think of this as the logical "midpoint" of the
\refdir{lib} code": much of the higher-level code is higher-level
_because_ it uses the logging module, and much of the lower-level code is
specifically written to avoid having to log, because the logging module
depends on it.


