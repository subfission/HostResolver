#!/usr/bin/env python3

"""
Copyright (c) 2017-2018, Zach Jetson All rights reserved.


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author: Zach Jetson
Date:   May 2017
Name:   resolv.py


Quickly resolve a large host file list to IP addresses and print them into a table.

Usage: ./resolv.py hostnames.txt [-h]

Requirements

* Python 3.0-6
* PrettyTable 0.7.x
* dnspython 1.15.x
* cymruwhois 1.6

Sample Output

$ ./resolv.py hostnames.txt

Resolving hosts from file [hostnames.txt]
+---------------+----------------+
| Hostname      | IP             |
+---------------+----------------+
| google.com    | 216.58.216.14  |
| yahoo.com     | 98.138.253.109 |
| outlook.com   | 40.97.156.114  |
| askjeeves.com | 66.235.121.240 |
+---------------+----------------+

"""

from time import sleep
import argparse
import csv
import ipaddress
import os
import re
import socket
import sys
import threading

try:
    from cymruwhois import Client
    from prettytable import PrettyTable
    import dns.resolver, dns.rdatatype, dns.exception

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 1.0
except ImportError as e:
    print(e)
    sys.exit("[!] Critical: Please run> pip3 install -r requirements")

RE_SPF = re.compile(r'v=spf1', re.IGNORECASE)
MAX_THREADS = 100
DEBUG = False


class Colorize():
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.BLUE = ''
        self.GREEN = ''
        self.RED = ''
        self.ENDC = ''


Colors = Colorize()


class DNSRecord():
    """
    DNSRecord manages DNS record actions and results
    """

    def __init__(self, hostname, args):
        self.result = [hostname]
        self.ip = None
        self.rtype = None
        self.hostname = hostname
        self.record = None
        self.spf = None
        self.args = args
        self.dead_host = False

    def __lt__(self, other: object) -> bool:
        return (self.hostname.casefold(), self.ip) < (other.hostname.casefold(), other.ip)

    def query(self):
        self.fetch_ip()
        self.dns_interrogate()

        return self.result

    def fetch_ip(self):

        try:
            self.ip = str(ipaddress.ip_address(self.result[0]))
        except ValueError:
            pass
        try:
            query_address = self.result[0]
            if self.ip:
                dprint("Resolving hostname from system: %s" % query_address)
                self.result[0] = socket.gethostbyaddr(query_address)[0]
            else:
                dprint("Resolving IP from system: %s" % query_address)
                self.ip = str(socket.gethostbyname(query_address))

            self.result.append(Colors.GREEN + self.ip + Colors.ENDC)
        except (socket.gaierror, socket.herror):
            self.ip = "unresolvable"
            self.dead_host = True
            self.result.append(Colors.RED + self.ip + Colors.ENDC)

    def dns_interrogate(self):
        try:
            query = resolver.query(self.result[0])
            type = dns.rdatatype.to_text(query.response.answer[0].rdtype)
            self.rtype = type
            record = '\n'.join(str(i) for i in query.response.answer)
            self.record = record

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            record = Colors.RED + "error" + Colors.ENDC
            type = Colors.RED + "error" + Colors.ENDC

        self.result.append(type)

        if self.args.non_cached:
            self.result.append(record)

        if self.args.spf:
            self.result.append(self.get_spf())

    def get_spf(self):
        try:
            query = resolver.query(self.result[0], "SPF")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            try:
                query = resolver.query(self.result[0], "TXT")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                return "TXT record not found"

        matches = [spf.to_text() for spf in query if RE_SPF.search(spf.to_text())]
        if matches:
            return "\n".join(matches)

        return "SPF data not found"


def get_asn(ips):
    dprint("Requesting ASNs for %d IPs" % len(ips))
    c = Client()
    return [x for x in c.lookupmany(ips)]


def build_host_table(table_columns, records):
    pretty_table = PrettyTable(table_columns)
    pretty_table.align = "l"
    pretty_table.align['RType'] = 'c'
    records.sort()
    for record in records:
        pretty_table.add_row(record.result)
    return pretty_table


def build_asn_table(records):
    pretty_table = PrettyTable(['IP', 'ASN', 'Range', 'CO', 'Owner'])
    pretty_table.align = "l"
    for asn in records:
        pretty_table.add_row([Colors.GREEN + asn.ip + Colors.ENDC, asn.asn, asn.prefix, asn.cc, asn.owner])
    return pretty_table


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False,
                                     description="""{}
           )               (
        ( /(           )   )\ )           (
        )\())       ( /(  (()/(  (        )\ )     (  (
       ((_)\  (  (  )\())  /(_))))\(   ( ((_)((   ))\ )(
        _((_) )\ )\(_))/  (_)) /((_)\  )\ _(_))\ /((_|())
       | || |((_|(_) |_   | _ (_))((_)((_) |)((_|_))  ((_)
       | __ / _ (_-<  _|  |   / -_|_-< _ \ \ V // -_)| '_|
       |_||_\___/__/\__|  |_|_\___/__|___/_|\_/ \___||_|

{}      This script will quickly resolve a list of hosts to IP
                addresses using multiple techniques.{}

                          By: Zach Jetson
               github: https://github.com/subfission

    """.format(Colors.RED, Colors.BLUE, Colors.ENDC), formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('--verbose', '-v', action='store_true', help="Outputs verbose record information")
    parser.add_argument('--non-cached', '-n', action='store_true', help="Include queries ignoring cached record data")
    parser.add_argument('--no-color', '-c', action='store_true', help="Disable colored output")
    parser.add_argument('resource', metavar='hostnames',
                        help="A hostname, IP, CSV, or return delimited file containing the host names for query.")
    parser.add_argument('--spf', action='store_true', help="Query for SPF records")
    parser.add_argument('--asn', action='store_true', help="Output ASN record for host or host list")
    parser.add_argument('--threads', '-t',
                        help='Set the maximum number of threads. (Recommended default is 50)',
                        dest='max_threads',
                        type=int,
                        default=50)
    parser.add_argument('--debug', '-d', action='store_true', help="Enable debug mode")

    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    if args.debug:
        global DEBUG
        DEBUG = True

    parser = Parser(args.resource)
    records = parser.parse()

    host_resolver = Resolver(args)
    host_resolver.resolve(records)


class Resolver:
    def __init__(self, args):
        self.max_threads = args.max_threads
        """
        Storage object for hosts
        """
        self.hosts = []
        self.args = args

    def resolve(self, records):
        table_columns = ['Hostname', 'IP (cached)', 'RType']

        if self.args.non_cached:
            dprint("Non-cached record search included...")
            table_columns.append('Record (non-cached)')
        if self.args.spf:
            table_columns.append('SPF Record')
            dprint("SPF record search included...")
        if self.args.asn:
            dprint("ASN record search included...")

        for hostname in records:
            try:
                self.build_query_from_record(hostname)
            except KeyboardInterrupt:
                self.max_threads = 0
                error("shutting down cleanly")
                self.end_thread_pool()

        self.end_thread_pool()
        table = build_host_table(table_columns, self.hosts)
        std_print(table)
        print("")

        if self.args.asn:
            pprint("Requesting ASNs from resolved host IP addresses")
            asn_list = get_asn([record.ip for record in self.hosts if not record.dead_host])
            table = build_asn_table(asn_list)
            std_print(table)

    def query(self, hostname):
        dns_record = DNSRecord(hostname, self.args)
        dns_record.query()
        self.hosts.append(dns_record)

        if self.args.verbose:
            pprint(", ".join(dns_record.result))

    def build_query_from_record(self, hostname):
        while threading.active_count() >= self.max_threads:
            sleep(2)

        pthread = threading.Thread(target=self.query, args=(hostname,))
        pthread.start()
        dprint("New thread started: %s" % threading.get_ident())

    @staticmethod
    def end_thread_pool():
        """
        Let threads finish and have them return their results

        :return: void
        """
        main_thread = threading.currentThread()
        for aThread in threading.enumerate():
            if aThread is main_thread:
                continue
            aThread.join()


class Parser:

    def __init__(self, resource):

        self.resource = resource.strip()

        if os.path.isfile(resource):
            if resource.endswith('.csv'):
                self.parse_mode = "csv_parser"
            else:
                self.parse_mode = "file_parser"
        else:
            self.parse_mode = "arg_parser"

    def parse(self):
        print()
        pprint("Resolving hosts from [ %s ]" % self.resource)
        try:
            parse_method = getattr(self, self.parse_mode)
            return parse_method()
        except FileNotFoundError:
            critical("File not found or readable.")

    def csv_parser(self):
        host_position = None
        with open(self.resource) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',', quotechar='"')

            header = next(csv_reader)

            # Assumed hostname resolution as primary
            host_position = [i for i, s in enumerate(header) if s.lower() in ['hostname', 'host', 'host name']][0]
            if not host_position:
                # Assumed IP resolution
                host_position = \
                    [i for i, s in enumerate(header) if s.lower() in ['ip', 'ip_addresses', 'ip addresses']][0]

            hosts = []
            for row in csv_reader:
                r_hosts = row[host_position].split(" ")
                if r_hosts:
                    hosts = list(set(hosts + r_hosts))

        return filter(None, hosts)

    def file_parser(self):
        with open(self.resource, "r") as host_file:
            hosts = [line.strip() for line in host_file]

        return hosts

    def arg_parser(self):
        return [self.resource]


def error(msg):
    std_print(Colors.RED + '[!] Error: %s' % msg + Colors.ENDC)


def critical(msg):
    std_print(Colors.RED + '[!] Critical: %s' % msg + Colors.ENDC)
    sys.exit(1)


def pprint(msg):
    std_print(Colors.GREEN + '[+] %s' % msg + Colors.ENDC)


def dprint(msg):
    if DEBUG:
        std_print(Colors.BLUE + '[+] %s' % msg + Colors.ENDC)


def std_print(msg):
    print(msg)


if __name__ == '__main__':
    main()
