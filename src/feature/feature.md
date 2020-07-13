@dir /feature
@brief feature: domain-specific modules

The "feature" directory has modules that Tor uses only for a particular
role or service, such as maintaining/using an onion service, operating as a
relay or a client, or being a directory authority.

Current subdirectories are:

   - \refdir{feature/api} -- Support for making Tor embeddable
   - \refdir{feature/client} -- Functionality which only Tor clients need
   - \refdir{feature/control} -- Controller implementation
   - \refdir{feature/dirauth} -- Directory authority
   - \refdir{feature/dircache} -- Directory cache
   - \refdir{feature/dirclient} -- Directory client
   - \refdir{feature/dircommon} -- Shared code between the other directory modules
   - \refdir{feature/dirparse} -- Directory parsing code.
   - \refdir{feature/hibernate} -- Hibernating when Tor is out of bandwidth
     or shutting down
   - \refdir{feature/hs} -- v3 onion service implementation
   - \refdir{feature/hs_common} -- shared code between both onion service
     implementations
   - \refdir{feature/keymgt} -- shared code for key management between
     relays and onion services.
   - \refdir{feature/nodelist} -- storing and accessing the list of relays on
     the network.
   - \refdir{feature/relay} -- code that only relay servers and exit servers
     need.
   - \refdir{feature/rend} -- v2 onion service implementation
   - \refdir{feature/stats} -- statistics and history
