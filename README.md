# HostResolver
Resolve hosts to IP addresses, scan for SPF records, and enumerate ASNs as quickly as possible; because time is of the essence.

This script is contained to a single python file for portability.

![HostResolver Screenshot](https://raw.githubusercontent.com/subfission/HostResolver/master/HostResolver.png)

## Requirements
* **Python 3.11+**

## Installation
First make sure you have python 3.4+ and the python package manger (pip).
    
    python3 --version
    which pip3
    
Download all the dependencies using the package manager:

    pip3 install -r requirements.txt
    
**Thats it!**

Optionally, you can use virtual_env or other tools to manage your packages.


## Usage

**Single host lookup**

    python3 resolv.py hostname
    
**Lookup list of hostnames from file**

    python3 resolve.py hostnames_file.txt
    
**Advanced usage: Resolve all record types From List to JSON**

    python3 resolv.py --asn --org --spf --cname --dkim --aaaa --mx --dmarc --reverse hostname_list.txt

**Setup script as an executable**

    chmod +x resolv.py && mv resolv.py resolv
    ./resolv -h
    
## Updates

- Updated support for newer Python 3.11+
- Supports DMARK & DKIM
- Uses async for even faster resolution
- Improved error handling
- Reverse lookups
- Most fields are toggleable
- Support for AAAA, MX, and CNAME host records
- New outputs: JSON, SQLite, CSV
- Verbose debug mode added

## Future

 - Flags indicating DNS config issues
 - SSL Ciphers per host
 