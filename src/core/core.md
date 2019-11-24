@dir /core
@brief core: main loop and onion routing functionality

The "core" directory has the central protocols for Tor, which every
client and relay must implement in order to perform onion routing.

It is divided into three lower-level pieces:

   - \refdir{core/crypto} -- Tor-specific cryptography.

   - \refdir{core/proto} -- Protocol encoding/decoding.

   - \refdir{core/mainloop} -- A connection-oriented asynchronous mainloop.

and one high-level piece:

   - \refdir{core/or} -- Implements onion routing itself.

