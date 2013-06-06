#!/usr/bin/env python
## Tested on Python 2.7
## Requires python-netaddr, python-dnspython and python-nmap
## Written by KamiNuvini - kami@nuvini.com
## 
## This program scans the given IPs for DNS Recursion. By default, we'll check if the IPs resolve google.com
## You can also use -host to do a lookup on other domains.
## The IPs that resolved the given domain will be displayed

import sys, argparse, netaddr, os.path, socket, dns.resolver, nmap

# Validate filename
def valid_file(parser, filename):
    if not os.path.isfile(filename):
        parser.error("Error! The file %s does not exist." %filename)
    else:
        return filename
           
# Convert & Validate 1-100 ranges
def ip_range(ip):
    try:
        r = []
        for i in list(netaddr.IPGlob(ip)):
            r.append(i)
        return r
    except netaddr.core.AddrFormatError:
        invalid_ips.append(ip)

# Convert & Validate /24 ranges
def ip_cidr(ip):
    try:
        r = []
        for i in list(netaddr.IPNetwork(ip)):
            r.append(i)
        return r
    except netaddr.core.AddrFormatError:
        invalid_ips.append(ip)
    
# Validate normal IPs
def ip_normal(ip):
    try:
        ip = netaddr.IPAddress(ip)
        if ip.is_unicast() == True:
            return ip
    except netaddr.core.AddrFormatError:
        invalid_ips.append(ip)

# Check if given hostname is valid by doing a DNS lookup on the hostname.
def host_fqdn(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

# Print all invalid ips
def print_invalid_ips():
    print "Error! The following IPs are invalid:"
    for i in invalid_ips:
        print i
    sys.exit(1)

# See if we can resolve the hostname through the nameserver
def lookup_hosts(ip):
    resolver.nameservers = [str(ip)]
    r = []
    try:
        for response in resolver.query(hostname, 'A'):
            r.append(response)
            lookup_result = "%s resolved to %r for the lookup of %s" % (ip, ', '.join(map(str,r)), hostname)
        if lookup_result != None:
            print lookup_result
            return ip
    except dns.exception.Timeout:
        pass

# Attempt to fingerprint the nameserver    
def dns_identify(ip):
    hosts = []
    unknown_hosts = []
    nm.scan(hosts=str(ip), arguments='-PN -sV -A -sU -p53')
    try:
        hosts += [(x, nm[x]['status']['state'], nm[x]['udp'][53]['script']['dns-nsid'].strip()) for x in nm.all_hosts()]
    except KeyError:
        unknown_hosts.append("%s is recursing, but couldn't determine running DNS software" % ip)
    for i in hosts:
        print "%s is %s and runs %s" % (i[0].encode("utf-8"), i[1].encode("utf-8"), i[2].encode("utf-8"))
    for i in unknown_hosts:
        print i

# Adding command-line options.
parser=argparse.ArgumentParser()
parser.add_argument('-v', action='version', version='%(prog)s - version 0.2', dest='version', help="Display the current version of the program.")
parser.add_argument('-host', nargs=1, dest='host', help="Override the default DNS lookup for google.com")
parser.add_argument('-i', nargs='+', dest='ips', help="IPs that have to be scanned. Comma separated.")
parser.add_argument('-f', nargs=1, dest='filename', metavar="FILE", type=lambda x: valid_file(parser, x), help="File with IPs that have to be scanned. Separated with newlines or commas.")
args = parser.parse_args()

# Print error message if there are no arguments.
if len(sys.argv) <= 1:
    parser.print_help()
    sys.exit(1)

# Assign list that will contain our valid & invalid ips.
invalid_ips = []
valid_ips = []
# Do the actual validation & conversion of items IPs
def ip_input(ips):
    for ip in ips:
        ip = ip.replace(",", "")
        if ip.count('.') != 3:
            invalid_ips.append(ip)
        elif '-' in ip:
            try:
                for i in ip_range(ip):
                    valid_ips.append(i)
            except TypeError:
                pass
        elif '/' in ip:
            try:
                for i in ip_cidr(ip):
                    valid_ips.append(i)
            except TypeError:
                pass
        else:
            try:
                valid_ips.append(ip_normal(ip))
            except TypeError:
                pass
        
# Assign the hostname we will perform a DNS lookup for. Override if -host is given.
hostname = 'google.com'
if args.host:
    if host_fqdn(args.host[0]) == True:
        hostname = args.host[0]
    else:
        print "Error! The FQDN '%s' is invalid or cannot be resolved." % args.host[0]
        sys.exit(1)

# If the -i flag is given, go to the ip_input function.
if args.ips:
    ips = args.ips
    ip_input(ips)

# If inputfile is given, strip the commas and replace them with newlines.
if args.filename:
    filename = args.filename[0]
    with open(filename, 'r') as f:
        ips =  f.read().replace(', ', "\n").splitlines()
    ip_input(ips)

# Exit if we have invalid ips
if len(invalid_ips) >= 1:
    print_invalid_ips()

# Remove duplicates & Sort valid_ips
if len(valid_ips) > 0:
    valid_ips =  sorted(set(valid_ips))
    
    # Now testing if it is recursing and print out the recursing servers.
    recursing_dns = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 1.0
    total = len(valid_ips)
    for ip in valid_ips:
        print total,"IPs left to test                       \r",
        sys.stdout.flush()
        total -= 1
        if lookup_hosts(ip) != None:
            recursing_dns.append(ip)
    
    # We only want to detect the running DNS version if there are any recursing servers.
    if len(recursing_dns) > 0:
        nm = nmap.PortScanner()
        rtotal = len(recursing_dns)
        for ip in recursing_dns:
            print "Scanning for running DNS software. %s IPs left.                            \r" % rtotal,
            sys.stdout.flush()
            rtotal -= 1
            dns_identify(ip)

sys.exit(0)
