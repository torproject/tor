@dir /feature/stats
@brief feature/stats: Relay statistics. Also, port prediction.

This module collects anonymized relay statistics in order to publish them in
relays' routerinfo and extrainfo documents.

Additionally, it contains predict_ports.c, which remembers which ports we've
visited recently as a client, so we can make sure we have open circuits that
support them.

