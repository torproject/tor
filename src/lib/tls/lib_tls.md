@dir /lib/tls
@brief lib/tls: TLS library wrappers

This module has compatibility wrappers around the library (NSS or OpenSSL,
depending on configuration) that Tor uses to implement the TLS link security
protocol.

It also implements the logic for some legacy TLS protocol usage we used to
support in old versions of Tor, involving conditional delivery of certificate
chains (v1 link protocol) and conditional renegotiation (v2 link protocol).

