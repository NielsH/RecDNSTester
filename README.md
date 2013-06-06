RecDNSTester
============

Python program to test DNS servers for recursion

This is my first program. It is probably inefficient and perhaps buggy.

```
## Tested on Python 2.7
## Requires python-netaddr, python-dnspython and python-nmap
## Written by KamiNuvini - kami@nuvini.com
## 
## This program scans the given IPs for DNS Recursion. By default, we'll check if the IPs resolve google.com
## You can also use -host to do a lookup on other domains.
## The IPs that resolved the given domain will be displayed
```


```
usage: RecDNSTester.py [-h] [-v] [-host HOST] [-i IPS [IPS ...]] [-f FILE]

optional arguments:
  -h, --help        show this help message and exit
  -v                Display the current version of the program.
  -host HOST        Override the default DNS lookup for google.com
  -i IPS [IPS ...]  IPs that have to be scanned. Comma separated.
  -f FILE           File with IPs that have to be scanned. Separated with
                    newlines or commas.
```
