@dir /core/mainloop
@brief core/mainloop: Non-onion-routing mainloop functionality

This module uses the event-loop code of \refdir{lib/evloop} to implement an
asynchronous connection-oriented protocol handler.

The layering here is imperfect: the code here was split from \refdir{core/or}
without refactoring how the two modules call one another.  Probably many
functions should be moved and refactored.

