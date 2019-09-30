
## Threads in Tor ##

Tor is based around a single main thread and one or more worker
threads.  We aim (with middling success) to use worker threads for
CPU-intensive activities and the main thread for our networking.
Fortunately (?) we have enough cryptography that moving what we can of the
cryptographic processes to the workers should achieve good parallelism under most
loads.  Unfortunately, we only have a small fraction of our
cryptography done in our worker threads right now.

Our threads-and-workers abstraction is defined in workqueue.c, which
combines a work queue with a thread pool, and integrates the
signalling with libevent.  Tor main instance of a work queue is
instantiated in cpuworker.c.  It will probably need some refactoring
as more types of work are added.

On a lower level, we provide locks with tor_mutex_t, conditions with
tor_cond_t, and thread-local storage with tor_threadlocal_t, all of
which are specified in compat_threads.h and implemented in an OS-
specific compat_\*threads.h module.

Try to minimize sharing between threads: it is usually best to simply
make the worker "own" all the data it needs while the work is in
progress, and to give up ownership when it's complete.

