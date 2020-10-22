@dir /lib/metrics
@brief lib/metrics: Metrics collection API

This module is used for adding "metrics" support to Tor.

Metrics are a collection of counters that are defined per-subsystem and
accessed through the MetricsPort. Each subsystem is responsible for populating
metrics store(s) and providing access to them through the `.get_metrics()`
call located in the `subsys_fns_t` object.

These metrics are meant to be extremely lightweight and thus can be accessed
without too much CPU cost.
