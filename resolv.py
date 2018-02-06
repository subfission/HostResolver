#!/usr/bin/env python3

"""
Author: Zach Jetson
Date:   May 2017
Name:   resolv.py


Quickly resolve a large host file list to IP addresses and print them into a table.

Usage: ./resolv.py hostnames.txt [-h]

Requirements

* Python 3.0-6
* PrettyTable 0.7.x
* dnspython 1.15.x

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



Copyright (c) 2017, Zach Jetson All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met: * Redistributions
of source code must retain the above copyright notice, this list of conditions and
the following disclaimer. * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution. * Neither the
name of the nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
"""

import socket, sys
import argparse
import os
import ipaddress
import re
import threading
from time import sleep

try:
    from prettytable import PrettyTable
except ImportError as e:
    print(e)
    sys.exit("[!] Please run: pip3 install prettytable")
try:
    import dns.resolver, dns.rdatatype, dns.exception
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 1.0
except ImportError as e:
    print(e)
    sys.exit("[!] Please run: pip3 install dnspython")


RE_SPF = re.compile(r'v=spf1',re.IGNORECASE)
MAX_THREADS = 100

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
        return ((self.hostname.casefold(), self.ip) < (other.hostname.casefold(), other.ip))


    def query(self):
        self.fetch_ip()
        self.dns_interrogate()

        return self.result

    def fetch_ip(self):

        try:
            host_ip = ipaddress.ip_address(self.result[0])
        except ValueError:
            host_ip = False

        try:
            if host_ip:
                query = self.result[0]
                name, alias, addresslist = socket.gethostbyaddr(query)
                self.result[0] = name
            else:
                query = socket.gethostbyname(self.result[0])

            self.ip = Colors.GREEN + query + Colors.ENDC
        except (socket.gaierror, socket.herror):
            self.ip = Colors.RED + "unresolvable" + Colors.ENDC
        self.result.append(self.ip)

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


def build_table(table_columns, records):
    pretty_table = PrettyTable(table_columns)
    pretty_table.align = "l"
    pretty_table.align['RType'] = 'c'
    records.sort()
    for record in records:
        pretty_table.add_row(record.result)
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
                        help="A hostname, IP, or file containing the host names for query.")
    parser.add_argument('--spf', action='store_true', help="Query for SPF records")
    parser.add_argument('--dead', action='store_true', help="Output only hosts without DNS records")
    parser.add_argument('--threads', '-t',
                             help='Set the maximum number of threads. (Recommended default is 50)',
                             dest='max_threads',
                             type=int,
                             default=50)

    args = parser.parse_args()

    resolver = Resolver(args)
    resolver.resolve()



class Resolver():
    def __init__(self, args, **kwargs):
        self.max_threads = args.max_threads
        self.hosts = Hosts()
        self.args = args

        

    def resolve(self):
        records = []

        table_columns = ['Hostname', 'IP (cached)', 'RType']
        if self.args.no_color:
            Colors.disable()
        if self.args.non_cached:
            table_columns.append('Record (non-cached)')
        if self.args.spf:
            table_columns.append('SPF Record')
            print(Colors.BLUE + "SPF record search included..." + Colors.ENDC)

        try:
            if os.path.isfile(self.args.resource):
                with open(self.args.resource, "r") as hostfile:
                    print(Colors.BLUE + "\n" + "Resolving hosts from file [" + self.args.resource + "]" + Colors.ENDC)
                    for line in hostfile:
                        record = line.strip()
                        if not record:
                            continue
                        records.append(record)
            else:
                print(Colors.BLUE + "\n" + "Resolving host from [" + self.args.resource + "]" + Colors.ENDC)
                record = self.args.resource.strip()
                records.append(record)
        except FileNotFoundError:
            sys.exit("[!] File not found or readable.")

        for hostname in records:
            self.build_query_from_record(hostname)

        self.end_thread_pool()

        table = build_table(table_columns, self.hosts.getHosts())
        print(table)
        print("\n")


    def query(self, hostname):
        dns_record = DNSRecord(hostname, self.args)
        dns_record.query()
        self.hosts.append(dns_record)

        if self.args.verbose:
            print("Acquired: " + ", ".join(dns_record.result))


    def build_query_from_record(self, hostname):
        while threading.active_count() >= self.max_threads:
            sleep(2)

        threading.Thread(target=self.query, args=(hostname,)).start()


    def end_thread_pool(self):
        """
        Let threads finish and have them return their results

        :return: void
        """
        main_thread = threading.currentThread()
        for aThread in threading.enumerate():
            if aThread is main_thread:
                continue
            aThread.join()
 


class Hosts():
    """
    Storage object for hosts
    """
    def __init__(self):
        self._hosts = []

    def append(self, host):
        self._hosts.append(host)

    def __len__(self):
        return len(self._hosts)

    def getHosts(self):
        return self._hosts



if __name__ == '__main__':
    main()
