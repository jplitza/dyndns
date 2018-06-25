import requests
import re
from ipaddress import IPv4Address, IPv6Address, IPv6Network, IPv6Interface


class AbstractAddressProvider:
    def get_ipv4_address(self):
        raise NotImplementedError()

    def get_ipv6_address(self):
        raise NotImplementedError()

    def get_ipv6_network(self):
        return IPv6Network(str(self.get_ipv6_address()) + '/64', False)


class ExternalAddressProvider(AbstractAddressProvider):
    addresses = {
        4: 'http://4.wieistmeineipv6.de/ip.php',
        6: 'http://6.wieistmeineipv6.de/ip.php',
    }

    def __init__(self, addresses=None):
        if addresses:
            self.addresses.update(addresses)

    def _get_url(self, version):
        r = requests.get(self.addresses[version])
        r.raise_for_status()
        return r.text.strip()

    def get_ipv4_address(self):
        return IPv4Address(self._get_url(4))

    def get_ipv6_address(self):
        return IPv6Address(self._get_url(6))


class FritzboxAddressProvider(AbstractAddressProvider):
    def __init__(self, address="169.254.1.1"):
        self.fritzbox_address = address

    def get_ipv4_address(self):
        data = """
            <?xml version='1.0' encoding='utf-8'?>
            <s:Envelope
                    s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'
                    xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'>
                <s:Body>
                    <u:GetExternalIPAddress
                        xmlns:u=urn:schemas-upnp-org:service:WANIPConnection:1
                        />
                </s:Body>
            </s:Envelope>
            """
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SoapAction": "{}#{}".format(
                "urn:schemas-upnp-org:service:WANIPConnection:1",
                "GetExternalIPAddress",
            )
        }
        r = requests.post(
            "http://{}:49000/igdupnp/control/WANIPConn1".format(
                self.fritzbox_address
            ),
            data=data,
            headers=headers,
        )
        r.raise_for_status()

        tagname = 'NewExternalIPAddress'
        m = re.search('(?<=<{0}>).*(?=</{0}>)'.format(tagname), r.text)
        if not m:
            raise RuntimeError("No IP address found in response")

        return IPv4Address(m.group(0))


class InterfaceAddressProvider(AbstractAddressProvider):
    def __init__(self, iface=None):
        if not iface:
            metric = 0xffffffff + 1
            with open('/proc/net/ipv6_route') as f:
                for line in f:
                    splits = line.split()
                    splits[0:6] = map(self._fromhex, splits[0:6])
                    if splits[0:4] != [0, 0, 0, 0]:
                        continue
                    if splits[5] < metric:
                        iface = splits[9]
                        metric = splits[5]

        if not iface:
            raise RuntimeError(
                "Couldn't determine interface to grab IP address from!")

        self.iface = iface

    @staticmethod
    def _fromhex(x):
        return int(x, 16)

    def get_ipv6_iface(self):
        with open('/proc/net/if_inet6') as f:
            for line in f:
                splits = line.split()
                address, devn, prefix, scope, flags = \
                    map(self._fromhex, splits[0:5])
                dev = splits[5]
                if dev != self.iface:
                    continue
                if scope != 0:    # scope != global
                    continue
                if flags & 0x01:  # secondary flag is set
                    continue
                if flags & 0x20:  # depcrecated flag is set
                    continue

                address = IPv6Address(address)
                if address.is_private:
                    continue

                return IPv6Interface("{}/{}".format(address, prefix))

    def get_ipv6_network(self):
        return self.get_ipv6_iface().network

    def get_ipv6_address(self):
        return self.get_ipv6_iface().ip


if __name__ == '__main__':
    import sys
    import inspect

    ipv4_addresses = {}
    ipv6_networks = {}

    for name, cls in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(cls) and name.endswith('AddressProvider'):
            instance = cls()
            try:
                ipv4_addresses[name] = instance.get_ipv4_address()
            except NotImplementedError:
                pass
            try:
                ipv6_networks[name] = instance.get_ipv6_network()
            except NotImplementedError:
                pass

    print(ipv4_addresses)
    print(ipv6_networks)
    assert len(set(ipv4_addresses.values())) == 1
    assert len(set(ipv6_networks.values())) == 1
