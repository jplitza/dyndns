#!/usr/bin/env python3

import sys
from argparse import ArgumentParser

import address_providers
from dns_updater import DNSUpdater


def main():
    parser = ArgumentParser(description="DynDNS updater")
    parser.add_argument('-4, --ipv4-provider', dest="ipv4")
    parser.add_argument('-6, --ipv6-provider', dest="ipv6")
    parser.add_argument(
        '--server',
        help='DNS server to send the update to.',
        default='127.0.0.1',
    )
    parser.add_argument(
        '--keyfile',
        help='TSIG keyfile to sign the DNS update request.',
        default='',
    )
    parser.add_argument(
        'zones',
        help='Zone(s) to update.',
        nargs='+',
        metavar='zone',
    )
    parser.add_argument(
        '--ttl',
        help='TTL of records to be updated',
        default=60,
    )
    args = parser.parse_args()

    if not args.ipv4 and not args.ipv6:
        parser.print_help()
        print('No address providers specified!')
        return 1

    # load all providers before doing anything with them
    providers = {}
    for protocol in ('ipv4', 'ipv6'):
        if not getattr(args, protocol):
            continue

        providers[protocol] = getattr(address_providers, getattr(args, protocol))()

    # let providers fetch addresses
    addresses = []
    if providers['ipv4']:
        addresses.append(providers['ipv4'].get_ipv4_address())
    if providers['ipv6']:
        addresses.append(providers['ipv6'].get_ipv6_network())

    # update zones
    updater = DNSUpdater(args.server, addresses, args.ttl, args.keyfile)
    for zone in args.zones:
        updater.update_zone(zone)

    return 0


if __name__ == '__main__':
    sys.exit(main())
