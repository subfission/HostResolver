# HostResolver
Resolve hosts to IP addresses, scan for SPF records, and enumerate ASNs as quickly as possible; because time is of the essence.

![HostResolver Screenshot](https://raw.githubusercontent.com/subfission/HostResolver/master/HostResolver.png)

## Requirements
* **Python 3.5+**

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
    
**Advanced usage: Resolve ASNs & SPF records From List and Set Custom Thread Counts**

    python3 resolv.py --threads 200 --asn --spf hostname_list.txt
    
*More threads will allow a faster execution, with a tradeoff of system resources.*


## Future

 - DMARK & DKIM results
 - Flags indicating DNS config issues
 - SSL Ciphers per host
 