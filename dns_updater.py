import dns.query
import dns.rdtypes
import dns.tsig
import dns.tsigkeyring
import dns.update
import dns.zone
from ipaddress import IPv4Address, IPv6Address


class DNSUpdater:
    def __init__(self, server, addresses, ttl=60, key=None, keyalgorithm=dns.tsig.HMAC_SHA256):
        if key:
            with open(key) as f:
                self.keyring = dns.tsigkeyring.from_text({
                    'dyndns': f.read()
                })
        else:
            self.keyring = None
        self.keyalgorithm = keyalgorithm
        self.ttl = ttl
        self.server = server
        self.ipv4addr = None
        self.ipv6net = None
        for address in addresses:
            if not address:
                continue

            if address.version == 4:
                if self.ipv4addr:
                    raise RuntimeError("More than one IPv4 address given!")
                self.ipv4addr = address

            elif address.version == 6:
                if self.ipv6net:
                    raise RuntimeError("More than one IPv6 network given!")
                self.ipv6net = address

    def _relocate_ipv6_host(self, host):
        return self.ipv6net.network_address + (
            int(self.ipv6net.hostmask) & int(host)
        )

    def _generate_update(self, zone):
        update = dns.update.Update(
            zone,
            keyring=self.keyring,
            keyalgorithm=self.keyalgorithm,
        )
        z = dns.zone.from_xfr(dns.query.xfr(self.server, zone))
        changed = False

        if self.ipv4addr:
            for name, ttl, rdata in z.iterate_rdatas('A'):
                if ttl != self.ttl:
                    continue

                if self.ipv4addr == IPv4Address(rdata.address):
                    continue

                update.replace(name, self.ttl, 'A', str(self.ipv4addr))
                changed = True

        if self.ipv6net:
            for name, ttl, rdata in z.iterate_rdatas('AAAA'):
                if ttl != self.ttl:
                    continue

                ipv6addr = self._relocate_ipv6_host(IPv6Address(rdata.address))
                if ipv6addr == IPv6Address(rdata.address):
                    continue

                update.replace(name, self.ttl, 'AAAA', str(ipv6addr))
                changed = True

        return update if changed else None

    def update_zone(self, zone):
        update = self._generate_update(zone)
        if update:
            dns.query.tcp(update, self.server)


if __name__ == '__main__':
    import sys
    from ipaddress import IPv6Network
    updater = DNSUpdater(
        '127.0.0.1',
        [
            IPv4Address('127.0.0.1'),
            IPv6Network('2001:0DB8::/64'),
        ],
    )
    print(updater._generate_update(sys.argv[1]))
