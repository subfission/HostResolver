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

* Python 3.11
* Rich 
* dnspython

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

import argparse
import asyncio
import csv
import re
import sqlite3
import sys
import traceback
from functools import lru_cache
from typing import Any, Dict, List

try:
    import dns.asyncresolver
    import dns.exception
    import dns.reversename
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.json import JSON
except ModuleNotFoundError as e:
    print(str(e), file=sys.stderr)
    print("Unable to import required module.", file=sys.stderr)
    print("Run 'pip3 install requirements.txt' to continue... ", file=sys.stderr)
    sys.exit(1)

console = Console()
resolver = dns.asyncresolver.Resolver(configure=True)
resolver.timeout = 2
resolver.lifetime = 2

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)

# === Async DNS Utilities ===

@lru_cache(maxsize=512)
def resolve_record_cached(domain: str, rtype: str):
    return domain, rtype

async def resolve_record(domain: str, rtype: str) -> List[str]:
    try:
        answers = await resolver.resolve(domain, rtype)
        return [r.to_text() for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []

async def reverse_lookup(ip: str) -> str:
    rev_name = dns.reversename.from_address(ip)
    answers = await resolver.resolve(rev_name, "PTR")
    return str(answers[0]) if answers else ""


@lru_cache(maxsize=512)
def get_asn_info_cached(ip: str):
    return ip

async def get_asn_info(ip: str) -> str:
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        answer = await resolver.resolve(query, "TXT")
        return str(answer[0]).strip('"').split(" | ")[0] if answer else ""
    except Exception as e:
        return str(e)

@lru_cache(maxsize=512)
def get_asn_org_cached(asn: str):
    return asn

async def get_asn_org(asn: str) -> str:
    try:
        query = f"AS{asn}.asn.cymru.com"
        answer = await resolver.resolve(query, "TXT")
        return str(answer[0]).strip('"').split(" | ")[4] if answer else ""
    except Exception as e:
        return str(e)

async def get_spf(domain: str) -> str:
    records = await resolve_record(domain, "TXT")
    return next((r for r in records if "v=spf" in r.lower()), "")

async def get_dmarc(domain: str) -> str:
    records = await resolve_record(f"_dmarc.{domain}", "TXT")
    return next((r for r in records if "v=dmarc" in r.lower()), "")

async def get_dkim(domain: str) -> str:
    selectors = ["default", "selector1", "selector2"]
    for selector in selectors:
        records = await resolve_record(f"{selector}._domainkey.{domain}", "TXT")
        for r in records:
            if "v=dkim1" in r.lower():
                return r
    return ""

def validate_domain(domain: str) -> bool:
    return DOMAIN_REGEX.fullmatch(domain) is not None

def load_targets(input_path: str) -> List[str]:
    try:
        if input_path.endswith(".csv"):
            with open(input_path, newline="") as f:
                reader = csv.DictReader(f)
                return [row[reader.fieldnames[0]] for row in reader if row[reader.fieldnames[0]]]
        else:
            with open(input_path) as f:
                return [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[red]Error loading input:[/red] {e}")
        sys.exit(1)

def save_to_sqlite(results: List[Dict[str, Any]], db_path: str, fields: List[str]):
    try:
        conn = sqlite3.connect(db_path)
        col_str = ", ".join([f"{col} TEXT" for col in fields])
        conn.execute(f"CREATE TABLE IF NOT EXISTS results ({col_str})")
        for row in results:
            placeholders = ", ".join(["?" for _ in fields])
            conn.execute(
                f"INSERT INTO results ({', '.join(fields)}) VALUES ({placeholders})",
                [row.get(col, "") for col in fields],
            )
        conn.commit()
        conn.close()
    except Exception as e:
        console.print(f"[red]SQLite error:[/red] {e}")

async def query_target(domain: str, opts: Dict[str, bool], debug: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {"TARGET": domain}
    errors = []
    if not validate_domain(domain):
        errors.append("Invalid domain format")
    else:
        try:
            if debug: console.log(f"Resolving A records for {domain}")
            a_records = await resolve_record(domain, "A")
            result["A"] = "\n".join(a_records)

            asn_list, org_list, reverse_list = [], [], []

            for ip in a_records:
                if debug: console.log(f"Getting ASN for {ip}")
                asn = await get_asn_info(ip)
                if asn:
                    asn_list.append(asn)
                    if opts.get("org"):
                        if debug: console.log(f"Getting ORG for ASN {asn}")
                        org = await get_asn_org(asn)
                        if org:
                            org_list.append(org)
                        else:
                            errors += ["No response for ASN org."]

                if opts.get("reverse"):
                    if debug: console.log(f"Getting reverse DNS for {ip}")
                    try:
                        rev = await reverse_lookup(ip)
                        if rev:
                            reverse_list.append(rev)
                    except Exception as e:
                        errors += [str(e)]
            if opts.get("asn"):
                result["ASN"] = "\n".join(asn_list)
            if org_list: result["ORG"] = "\n".join(org_list)
            if reverse_list: result["Reverse"] = "\n".join(reverse_list)

            for rtype in ["AAAA", "CNAME", "MX"]:
                if opts.get(rtype.lower()):
                    if debug: console.log(f"Resolving {rtype} for {domain}")
                    records = await resolve_record(domain, rtype)
                    if not records:
                        errors += ["No answer for " + rtype + " request."]
                    result[rtype] = "\n".join(records)

            if opts.get("spf"):
                if debug: console.log(f"Getting SPF for {domain}")
                result["SPF"] = await get_spf(domain)
                if not result["SPF"]: errors += ["No response for SPF."]
            if opts.get("dmarc"):
                if debug: console.log(f"Getting DMARC for {domain}")
                result["DMARC"] = await get_dmarc(domain)
                if not result["DMARC"]: errors += ["No response for DMARC."]
            if opts.get("dkim"):
                if debug: console.log(f"Getting DKIM for {domain}")
                result["DKIM"] = await get_dkim(domain)
                if not result["DKIM"]: errors += ["No response for DKIM."]

        except Exception as e:
            errors += str(e)
            if debug:
                result["TRACE"] = traceback.format_exc()

    result["ERROR"] = "\n".join(errors)
    return result

async def main():
    parser = argparse.ArgumentParser(allow_abbrev=False, 
                                     description=r"""{}
           )               (
        ( /(           )   )\ )           (
        )\())       ( /(  (()/(  (        )\ )     (  (
       ((_)\  (  (  )\())  /(_))))\(   ( ((_)((   ))\ )(
        _((_) )\ )\(_))/  (_)) /((_)\  )\ _(_))\ /((_|())
       | || |((_|(_) |_   | _ (_))((_)((_) |)((_|_))  ((_)
       | __ / _ (_-<  _|  |   / -_|_-< _ \ \ V // -_)| '_|
       |_||_\___/__/\__|  |_|_\___/__|___/_|\_/ \___||_|  v2
{}
 This utility script will perform rapid domain resolution at scale.
{}
                                                  By: Zach Jetson
                            Github: https://github.com/subfission

    """.format('\033[91m', '\033[94m', '\033[0m'), formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("input", help="A hostname, IP, CSV, or path to or return delimited file containing valid hostnames.")

    # Resolver Configuration
    parser.add_argument("--timeout", type=int, default=3)
    parser.add_argument("--nocolor", action="store_true", help="Disable colored output")
    parser.add_argument("--debug", action="store_true", help="Outputs verbose record information")

    # Optionals
    parser.add_argument("--asn", action='store_true', help="Retrieve ASN record(s)")
    parser.add_argument("--org", action="store_true", help="Retrieve the ASN organization")

    parser.add_argument("--aaaa", action="store_true", help="Retrieve the DNS AAAA record")
    parser.add_argument("--cname", action="store_true", help="Retrieve the DNS CNAME record")
    parser.add_argument("--mx", action="store_true", help="Retrieve the DNS MX record")
    parser.add_argument("--spf", action='store_true', help="Retrieve the DNS SPF record(s)")
    parser.add_argument("--dmarc", action='store_true', help="Retrieve DNS DMARC record")
    parser.add_argument("--dkim", action="store_true", help="Retrieve the DNS DKIM record")
    parser.add_argument("--reverse", action="store_true", help="Retrieve the DNS reverse lookup record")
    
    # Outputs
    parser.add_argument("--json", action='store_true', help="Output as JSON directly")
    parser.add_argument("--csv", help="Output CSV path")
    parser.add_argument("--sqlite", help="Output SQLite DB path")
    parser.add_argument("--error", action="store_true", help="Display record lookup errors in table output")

    args = parser.parse_args()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout
    opts = vars(args)

    if validate_domain(args.input) or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", args.input):
        targets = [args.input]
    else:
        targets = load_targets(args.input)

    results = []
    errors = 0
    debug = args.debug

    with Progress(SpinnerColumn(), BarColumn(), TextColumn("{task.description}"), TimeElapsedColumn(),
        transient=True, console=console
    ) as progress:
        task = progress.add_task("Querying...", total=len(targets))
        for t in targets:
            res = await query_target(t, opts, debug)
            results.append(res)
            if "ERROR" in res: errors += 1
            progress.advance(task)

    base_fields = ["TARGET", "A"]
    extra_fields = [f.upper() for f in ["asn","org", "aaaa", "cname", "mx", "spf", "dmarc", "dkim", "reverse", "error"] if opts.get(f)]
    fields = base_fields + extra_fields

    table = Table(show_header=True, expand=True, header_style="bold green" if not args.nocolor else "")
    for field in fields:
        table.add_column(field)
    
    for row in results:
        table.add_row(*(row.get(f, "") for f in fields))

    if not args.json:
        console.print(table)
        console.print(f"\n[green]Completed:[/green] {len(results)} domain | [red]Record With Errors:[/red] {errors}")

    if args.json:
        console.print(JSON.from_data(results), highlight=True)

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(results)
    if args.sqlite:
        save_to_sqlite(results, args.sqlite, fields)

if __name__ == "__main__":
    asyncio.run(main())
