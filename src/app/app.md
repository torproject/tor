@dir /app
@brief app: top-level entry point for Tor

The "app" directory has Tor's main entry point and configuration logic,
and is responsible for initializing and managing the other modules in
Tor.

The modules in "app" are:

   - \refdir{app/config} -- configuration and state for Tor
   - \refdir{app/main} -- Top-level functions to invoke the rest or Tor.
