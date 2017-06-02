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

try:
    from prettytable import PrettyTable
except ImportError as e:
    print(e)
    sys.exit("[!] Please run: pip install prettytable")
try:
    import dns.resolver
except ImportError as e:
    print(e)
    sys.exit("[!] Please run: pip install dnspython")


class Colors():
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'


class DNSRecord():
    def __init__(self, hostname):
        self.result = [hostname]

    def fetch_ip(self):
        try:
            ip = Colors.GREEN + socket.gethostbyname(self.result[0]) + Colors.ENDC
        except socket.gaierror:
            ip = Colors.RED + "unresolvable" + Colors.ENDC
        self.result.append(ip)

    def dns_query(self, verbose=False):
        try:
            query = dns.resolver.query(self.result[0])
            type = dns.rdatatype.to_text(query.response.answer[0].rdtype)
            record = '\n'.join(str(i) for i in query.response.answer)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            record = Colors.RED + "error" + Colors.ENDC
            type = Colors.RED + "error" + Colors.ENDC

        self.result.append(type)

        if verbose:
            self.result.append(record)


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
    parser.add_argument('filename', metavar='hostnames', help="The file containing the host names for query.")
    args = parser.parse_args()

    table_columns = ['Hostname', 'IP (cached)', 'RType']

    if args.verbose:
        table_columns.append('Record (non-cached)')

    pretty_table = PrettyTable(table_columns)
    pretty_table.align = "l"
    pretty_table.align['RType'] = 'c'

    try:
        with open(args.filename, "r") as hostfile:
            print(Colors.BLUE + "\n" + "Resolving hosts from file [" + args.filename + "]" + Colors.ENDC)
            for line in hostfile:

                hostname = line.strip()
                if not hostname:
                    continue

                dns_record = DNSRecord(hostname)
                dns_record.fetch_ip()
                dns_record.dns_query(args.verbose)
                pretty_table.add_row(dns_record.result)

    except FileNotFoundError:
        sys.exit("[!] File not found or readable.")

    print(pretty_table)

    print("\n")


if __name__ == '__main__':
    main()
