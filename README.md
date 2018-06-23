IPv4/IPv6 DynDNS client
=======================

Can get IP addresses from one of several sources:

* External websites
* Network interface of local machine (if there are multiple, the one with the
  default route)
* Fritz!Box API

Not only a single DNS entry/record pair is updated, but first an AXFR transfer
of the whole zone is done, and then every record with a given (short) TTL is
updated. For IPv4, the records are replaced. For IPv6, the host portion of the
records is kept intact, while the network portion is updated.
