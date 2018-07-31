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

import sys
from time import sleep

import argparse
import csv
import ipaddress
import os
import re
import socket
import threading

try:
    from cymruwhois import Client
    from prettytable import PrettyTable
    import dns.resolver
    import dns.rdatatype
    import dns.exception

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 1.0
except ImportError as e:
    print(e)
    sys.exit("[!] Critical: Please run> pip3 install -r requirements.txt")

RE_SPF = re.compile(r'v=spf1', re.IGNORECASE)
RE_SPF_MECH = re.compile(r'^(?:include|exists|ptr|a|mx):', re.MULTILINE | re.IGNORECASE)
RE_DMARC = re.compile(r'v=DMARC1', re.IGNORECASE)

MAX_THREADS = 100
DEBUG = False


def error(msg):
    stdout(Colors.RED + '[!] Error: %s' % msg + Colors.ENDC)


def critical(msg):
    stdout(Colors.RED + '[!] Critical: %s' % msg + Colors.ENDC)
    sys.exit(1)


def info(msg):
    stdout(Colors.GREEN + '[+] %s' % msg + Colors.ENDC)


def debug(msg):
    if DEBUG:
        stdout(Colors.BLUE + '[+] %s' % msg + Colors.ENDC)


def stdout(msg):
    print(msg)


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

    UNRESOLVABLE = 'unresolvable'
    ERROR = 'error'
    MISSING_TXT = 'txt records not found'

    def __init__(self, hostname, **kwargs):
        # Flags for results and searches
        self.inc_uncached = kwargs.get("uncached", False)
        self.inc_spf = kwargs.get("spf", False)
        self.inc_dmarc = kwargs.get("dmarc", False)
        self.verbose = kwargs.get("verbose", False)

        # Storage variables
        self.result = [hostname]
        self.ip = None
        self.rtype = None
        self.hostname = hostname
        self.record = None
        self.spf = None
        self.as_number = None
        self.as_cidr = None
        self.as_country = None
        self.asn_org = None
        self.dmarc = None
        self.dead_host = False

    def __lt__(self, other: object) -> bool:
        return (self.hostname.casefold(), self.ip) < (other.hostname.casefold(), other.ip)

    def get_results(self):
        results = []
        if self.hostname == DNSRecord.UNRESOLVABLE:
            results.append(Colors.RED + self.hostname + Colors.ENDC)
        else:
            results.append(self.hostname)

        if self.ip in (DNSRecord.UNRESOLVABLE, DNSRecord.ERROR):
            results.append(Colors.RED + self.ip + Colors.ENDC)
        else:
            results.append(Colors.GREEN + self.ip + Colors.ENDC)

        if self.rtype == DNSRecord.ERROR:
            results.append(Colors.RED + self.rtype + Colors.ENDC)
        else:
            results.append(self.rtype)

        if self.inc_uncached:
            results.append(self.record)

        if self.spf:
            if self.spf in (DNSRecord.ERROR, DNSRecord.UNRESOLVABLE, DNSRecord.MISSING_TXT):
                results.append(Colors.RED + self.spf + Colors.ENDC)
            else:
                results.append(self.spf)

        if self.dmarc:
            if self.dmarc in (DNSRecord.ERROR, DNSRecord.UNRESOLVABLE, DNSRecord.MISSING_TXT):
                results.append(Colors.RED + self.dmarc + Colors.ENDC)
            else:
                results.append(self.dmarc)

        return results

    def fetch_ip(self):

        try:
            self.ip = str(ipaddress.ip_address(self.hostname))
        except ValueError:
            pass
        try:
            if self.ip:
                debug("Resolving hostname from system: %s" % self.ip)
                self.hostname = socket.gethostbyaddr(self.ip)[0]
            else:
                debug("Resolving IP from system: %s" % self.hostname)
                self.ip = str(socket.gethostbyname(self.hostname))

        except (socket.gaierror, socket.herror):
            if self.ip:
                self.hostname = DNSRecord.UNRESOLVABLE
            else:
                self.ip = DNSRecord.UNRESOLVABLE
            self.dead_host = True

    def dns_interrogate(self):
        try:
            if self.hostname == DNSRecord.UNRESOLVABLE:
                dns.exception.DNSException("")
            query = resolver.query(self.result[0])
            self.rtype = dns.rdatatype.to_text(query.response.answer[0].rdtype)
            if self.verbose:
                self.record = '\n'.join(str(i) for i in query.response.answer)
            else:
                self.record = str(query.response.answer[0])

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            self.record = "error"
            self.rtype = DNSRecord.ERROR

    def get_spf(self):
        try:
            if self.hostname == DNSRecord.UNRESOLVABLE:
                query = dns.resolver.query(self.ip, "TXT")
            else:
                query = dns.resolver.query(self.hostname, "TXT")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            self.spf = DNSRecord.MISSING_TXT
            return

        spf_results = []
        perm_err = False

        for q in query:
            if RE_SPF.search(q.to_text()):
                debug(q.to_text())
                parts = q.to_text().strip('"').strip().split(" ")
                if len(parts) > 1:
                    spf_results.append( "SPF Parts: "+ "\n> ".join(parts))
                else:
                    spf_results.append( "\n".join(parts))

        if not spf_results:
            self.spf = DNSRecord.UNRESOLVABLE
            return

        if len(spf_results) > 1:
            perm_err = True
            debug("SPF PermErr: multiple SPF records detected")

        spf_results = "".join(spf_results)
        if len(RE_SPF_MECH.findall(spf_results)) > 10:
            debug("SPF PermErr: greater than 10 mechanisms detected")
            perm_err = True

        if perm_err:
            self.spf = Colors.RED + "PermErr\n" + Colors.ENDC + "".join(spf_results)
        else:
            self.spf = "".join(spf_results)

    def get_dmarc(self):
        if self.dead_host:
            self.dmarc = DNSRecord.ERROR
            return
        try:
            qstr = "_dmarc." + self.hostname
            debug("Checking %s" % qstr)
            query = dns.resolver.query(qstr, "TXT")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            self.dmarc = DNSRecord.MISSING_TXT
            return

        for q in query:
            if RE_DMARC.search(q.to_text()):
                debug(q.to_text())
                self.dmarc = "\n".join(q.to_text().strip('"').split("; ")[1:])
                return

        self.dmarc = DNSRecord.ERROR

    def get_asn(self):
        if self.ip == DNSRecord.UNRESOLVABLE:
            self.as_number = DNSRecord.UNRESOLVABLE
            return

        try:
            cymru_host_query = ".".join(list(reversed(self.ip.split(".")))) + ".origin.asn.cymru.com"
            asn_resolver = dns.resolver.query(cymru_host_query, "TXT")
            self.as_number, self.as_cidr, self.as_country, _, _ = asn_resolver[0].to_text().strip("\"").split(" | ")
        except dns.resolver.NXDOMAIN:
            self.as_number = DNSRecord.UNRESOLVABLE
            return

        # get asn org
        try:
            asn_resolver = dns.resolver.query("AS" + self.as_number + ".asn.cymru.com", "TXT")
            self.as_number, self.as_cidr, self.as_country, _, _ = asn_resolver[0].to_text().strip("\"").split(" | ")
        except dns.resolver.NXDOMAIN:
            self.asn_org = DNSRecord.UNRESOLVABLE
            return


def get_asn(ips):
    debug("Requesting ASNs for %d IPs" % len(ips))
    c = Client()
    return [x for x in c.lookupmany(ips)]


def build_table(table_columns=[], records=[]):
    if len(records) == 0:
        critical("No targets were available for resolution")
    if type(records[0]) is DNSRecord:
        pretty_table = PrettyTable(table_columns)
        pretty_table.align = "l"
        pretty_table.align['RType'] = 'c'
        records.sort()
        for record in records:
            debug(", ".join(record.get_results() ))
            pretty_table.add_row(record.get_results())
        return pretty_table
    else:
        pretty_table = PrettyTable(table_columns)
        pretty_table.align = "l"
        for asn in records:
            pretty_table.add_row([asn.ip, Colors.GREEN + asn.asn + Colors.ENDC, asn.prefix, asn.cc, asn.owner])
        return pretty_table


class HostResolver:
    def __init__(self, args):
        self.max_threads = args.max_threads
        """
        Storage object for hosts
        """
        self.hosts = []
        self.args = args

    def resolve(self, records):
        table_columns = ['Hostname', 'IP', 'RType']

        if not records or len(records) < 1:
            critical("Invalid hosts")

        if self.args.uncached:
            debug("Uncached record search included...")
            table_columns.append('DNS Record (uncached)')
        if self.args.spf:
            table_columns.append('SPF')
            debug("SPF record search included...")
        if self.args.dmarc:
            table_columns.append('DMARC')
            debug("DMARC record search included...")
        if self.args.asn:
            debug("ASN record search included...")

        for hostname in records:
            try:
                self.build_query_from_record(hostname)
            except KeyboardInterrupt:
                self.max_threads = 0
                error("shutting down cleanly")
                self.end_thread_pool()

        self.end_thread_pool()

        table = build_table(table_columns=table_columns, records=self.hosts)
        stdout(table)
        print()

        if self.args.asn:
            salvageable_host_ips = [record.ip for record in self.hosts if not record.dead_host]
            if len(salvageable_host_ips) == 0:
                error("No IPs available for ASN resolution")
            else:
                info("Requesting ASNs from %d resolved host IP addresses" % len(salvageable_host_ips))
                asn_list = get_asn(salvageable_host_ips)
                table = build_table(table_columns=['IP', 'ASN', 'Range', 'CO', 'Owner'], records=asn_list)
                stdout(table)

    def query(self, hostname):
        dns_record = DNSRecord(hostname, spf=self.args.spf, uncached=self.args.uncached)
        dns_record.fetch_ip()
        dns_record.dns_interrogate()
        if self.args.spf:
            dns_record.get_spf()
        if self.args.dmarc:
            dns_record.get_dmarc()

        self.hosts.append(dns_record)
        if self.args.verbose:
            info(", ".join(dns_record.result))

    def build_query_from_record(self, hostname):
        while threading.active_count() >= self.max_threads:
            sleep(2)

        pthread = threading.Thread(target=self.query, args=(hostname,))
        pthread.start()

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

        debug("Waiting for threads to finish")


class Parser:

    def __init__(self, resource):

        self.resource = resource.strip()

        if os.path.isfile(resource):
            if resource.endswith('.csv'):
                debug("CSV parsing mode")
                self.parse_mode = "csv_parser"
            else:
                debug("File parsing mode")
                self.parse_mode = "file_parser"
        else:
            debug("Argument parsing mode")
            self.parse_mode = "arg_parser"

    def parse(self):
        print()
        info("Resolving hosts from [ %s ]" % self.resource)
        try:
            parse_method = getattr(self, self.parse_mode)
            return parse_method()
        except (IOError, FileNotFoundError) as err:
            critical("Error reading file %s: %s" % (self.resource, err))

    def csv_parser(self):
        """
        Parse CSV file into an list of targets.  Targets can be hostnames or IP addresses.

        Exceptions raised for file IO errors
        :return:
        """
        with open(self.resource) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',', quotechar='"')

            header = next(csv_reader)

            # Assumed hostname resolution as primary
            try:
                host_position = [i for i, s in enumerate(header) if s.lower() in ['hostname', 'host', 'host name']][0]
            except IndexError:
                host_position = False
            if not host_position:
                # Assumed IP resolution
                try:
                    host_position = \
                        [i for i, s in enumerate(header) if s.lower() in ['ip', 'ip_addresses', 'ip addresses']][0]
                except IndexError:
                    debug("No hosts found or missing headers in file")
                    return None

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
    parser.add_argument('--uncached', '-u', action='store_true', help="Include queries ignoring cached record data")
    parser.add_argument('--no-color', '-c', action='store_true', help="Disable colored output")
    parser.add_argument('resource', metavar='hostnames',
                        help="A hostname, IP, CSV, or return delimited file containing the host names for query.")
    parser.add_argument('--spf', action='store_true', help="Query for SPF records")
    parser.add_argument('--asn', action='store_true', help="Output ASN record for host or host list")
    parser.add_argument('--dmarc', action='store_true', help="Output DMARC record for host or host list")
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

    host_resolver = HostResolver(args)
    host_resolver.resolve(records)


if __name__ == '__main__':
    main()
