
@page certificates Certificates in Tor

We have, alas, several certificate types in Tor.

The tor_x509_cert_t type represents an X.509 certificate. This document
won't explain X.509 to you -- possibly, no document can. (OTOH, Peter
Gutmann's "x.509 style guide", though severely dated, does a good job of
explaining how awful x.509 can be.)  Do not introduce any new usages of
X.509. Right now we only use it in places where TLS forces us to do so.
See x509.c for more information about using this type.


The authority_cert_t type is used only for directory authority keys. It
has a medium-term signing key (which the authorities actually keep
online) signed by a long-term identity key (which the authority operator
had really better be keeping offline).  Don't use it for any new kind of
certificate.

For new places where you need a certificate, consider tor_cert_t: it
represents a typed and dated _something_ signed by an Ed25519 key.  The
format is described in tor-spec. Unlike x.509, you can write it on a
napkin.  The torcert.c file is used for manipulating these certificates and
their associated keys.

(Additionally, the Tor directory design uses a fairly wide variety of
documents that include keys and which are signed by keys. You can
consider these documents to be an additional kind of certificate if you
want.)
