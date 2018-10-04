#!/usr/bin/python3

import argparse
import email.utils as eut
import hashlib
import logging
import os
import re
import subprocess
import textwrap
from datetime import datetime
from pathlib import Path

import dns.name
import dns.zone
import requests
from dns.exception import DNSException

logger = logging.getLogger(__name__)

config = {
    # Blocklist download request timeout
    'req_timeout_s': 50,
    # Also block *.domain.tld
    'wildcard_block': False
}

regex_domain_with_ip = "^(0.0.0.0|127.0.0.1)\s+(?P<domain>([a-z0-9_-]+\.)+[a-z]+)"
regex_extract_domain = "(?P<domain>^[a-z0-9-.]+\.[a-z]{1,})\s*.*$"
regex_domain_from_url = "(https?:\/\/)?(www\.)?(?P<domain>[a-zA-Z0-9-.]+)"

lists = [
    {'url': 'https://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=0', 'regex': regex_extract_domain},
    {'url': 'http://mirror1.malwaredomains.com/files/justdomains', 'regex': regex_extract_domain},
    {'url': 'http://winhelp2002.mvps.org/hosts.txt', 'regex': regex_domain_with_ip},
    {'url': 'https://adaway.org/hosts.txt', 'regex': regex_domain_with_ip},
    {'url': 'http://someonewhocares.org/hosts/zero/hosts', 'regex': regex_domain_with_ip},
    {'url': 'http://www.malwaredomainlist.com/hostslist/hosts.txt', 'regex': regex_domain_with_ip},
    # StevenBlack's list
    {'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'regex': regex_domain_with_ip},
    # Cameleon
    {'url': 'http://sysctl.org/cameleon/hosts', 'regex': regex_domain_with_ip},
    # Zeustracker
    {'url': 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist', 'regex': regex_extract_domain},
    # hpHosts
    {'url': 'https://hosts-file.net/download/hosts.txt', 'regex': regex_domain_with_ip},
    # OpenPhish
    {'url': 'https://openphish.com/feed.txt', 'regex': regex_domain_from_url},
    # CyberCrime tracker
    {'url': 'http://cybercrime-tracker.net/all.php', 'regex': regex_domain_from_url}, # TODO: ip addresses are still there
    # Free Ads BL from SquidBlacklist
    {'url': 'http://www.squidblacklist.org/downloads/dg-ads.acl', 'regex': regex_extract_domain},

    # Disconnect.me
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt', 'regex': regex_extract_domain},
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt', 'regex': regex_extract_domain},
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt', 'regex': regex_extract_domain},
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt', 'regex': regex_extract_domain},

    # Tracking & Telemetry & Advertising
    {'url': 'https://v.firebog.net/hosts/Easyprivacy.txt', 'regex': regex_extract_domain},
    {'url': 'https://v.firebog.net/hosts/Easylist.txt', 'regex': regex_extract_domain},
    {'url': 'https://v.firebog.net/hosts/AdguardDNS.txt', 'regex': regex_extract_domain},

    # Malicious list
    {'url': 'http://v.firebog.net/hosts/Shalla-mal.txt', 'regex': regex_extract_domain},
    {'url': 'https://v.firebog.net/hosts/Cybercrime.txt', 'regex': regex_extract_domain},
    {'url': 'https://v.firebog.net/hosts/APT1Rep.txt', 'regex': regex_extract_domain},
    {'url': 'http://www.joewein.net/dl/bl/dom-bl.txt', 'regex': regex_extract_domain},
    {'url': 'https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt', 'regex': regex_extract_domain},

    # Other stuff from notrack-blocklists
    {'url': 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt', 'regex': regex_extract_domain},
    {'url': 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt', 'regex': regex_extract_domain}
]


def set_log_level(verbosity: int) -> None:
    log_level = logging.WARNING  # default
    if verbosity == 2:
        log_level = logging.INFO
    elif verbosity >= 3:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def quiet_mode() -> None:
    log_level = logging.FATAL
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def print_usage(zonefile: str, origin: str) -> None:
    current_log_level = logging.getLogger().getEffectiveLevel()

    logging.getLogger().setLevel(logging.INFO)
    path = Path(zonefile).resolve()

    logger.info(textwrap.dedent(f'''
            Zone file "{path}" created.

            Add BIND options entry:
            response-policy {{
                zone "{origin}"
            }};

            Add BIND zone entry:
            zone "{origin}" {{
                type master;
                file "{path}";
                allow-query {{ none; }};
            }};'''))

    logging.getLogger().setLevel(current_log_level)


def download_list(url: str):
    headers = None

    cache = Path('.cache', 'bind_adblock')
    if not cache.is_dir():
        cache.mkdir(parents=True)
    cache = Path(cache, hashlib.sha1(url.encode()).hexdigest())

    if cache.is_file():
        last_modified = datetime.utcfromtimestamp(cache.stat().st_mtime)
        headers = {
            'If-modified-since': eut.format_datetime(last_modified),
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'
        }

    try:
        r = requests.get(url, headers=headers, timeout=config['req_timeout_s'])

        if r.status_code == 200:
            with cache.open('w') as f:
                f.write(r.text)

            if 'last-modified' in r.headers:
                last_modified = eut.parsedate_to_datetime(r.headers['last-modified']).timestamp()
                os.utime(str(cache), times=(last_modified, last_modified))

            return r.text
        elif r.status_code != 304:
            logger.error(f'''Error getting list at {url} HTTP STATUS: {r.status_code}''')
    except requests.exceptions.RequestException as e:
        logger.error(e)

    if cache.is_file():
        with cache.open() as f:
            return f.read()


def check_domain(domain: str, origin: dns.name.Name) -> bool:
    if domain == '':
        return False
    try:
        dns.name.from_text(domain, origin)
    except DNSException:
        return False
    return True


def parse_lists(origin: str) -> str:
    domains = set()
    origin_name = dns.name.from_text(origin)
    for l in lists:
        data = download_list(l['url'])
        if data:
            logger.info(l["url"])

            logger.info(f'''\t {len(data.splitlines()):5} lines in file''')

            # lowering since DNS is case insensitive
            data = data.lower()

            # remove empty lines and comment only lines
            comment_lines = re.findall('^(\s|\t)*#.*|^\s+', data, re.MULTILINE)
            data = re.sub('^(\s|\t)*#.*\n|^\n', '', data, flags=re.MULTILINE)
            data = re.sub('\n{2,}', '\n', data)
            logger.info(f'''\t {len(comment_lines):5} empty lines or lines with comments removed''')

            lines = data.splitlines()
            logger.info(f'''\t {len(lines):5} are now processed''')

            c = len(domains)

            counter_already_present_lines = 0
            for line in data.splitlines():
                domain = ''

                if 'regex' in l:
                    m = re.match(l['regex'], line)
                    if m:
                        domain = m.group('domain')
                    else:
                        logger.debug(f'''\t\t no match found in line "{line}"''')
                else:
                    domain = line

                domain = domain.strip()
                if check_domain(domain, origin_name):
                    if domain not in domains:
                        domains.add(domain)
                    else:
                        # logger.debug(f''''\t\t domain "{domain}" already in blacklist''')
                        counter_already_present_lines += 1

            logger.info(f'''\t {counter_already_present_lines:5} were already on the blacklist''')
            logger.info(f'''\t {(len(domains) - c):5} domains were added to blacklist''')

    logger.info(f'''Blacklist contains {len(domains):6} domains ''')
    return domains


def create_header_for_zonefile(origin: str) -> dns.zone.Zone:
    now = datetime.now()

    zone_text = f'''$TTL 8600
@ IN SOA  admin. postmaster.{origin}. (
        {now.year}{now.month}{now.day}01    ; Serial number
                             3600           ; Refresh 1 hour
                              600           ; retry 10 minutes
                            86400           ; expiry 24 hours'
                              600 )         ; min ttl 10 minutes

@ IN NS   LOCALHOST.'''

    return dns.zone.from_text(zone_text, origin)


def update_serial(zone: dns.zone.Zone) -> None:
    soa = zone.get_rdataset('@', dns.rdatatype.SOA)[0]
    soa.serial += 1


def reload_zone(origin):
    r = subprocess.call(['rndc', 'reload', origin])
    if r != 0:
        raise Exception(f'''rndc failed with return code {r}''')


parser = argparse.ArgumentParser()

parser.add_argument('zonefile', help='name of the generated file', type=str)
parser.add_argument('origin', help='name of the zone', type=str)

group = parser.add_mutually_exclusive_group()
group.add_argument('-v', '--verbose', action='count',
                   help='increase verbosity (specify multiple times for more output)')
group.add_argument('-q', '--quiet', action='store_true', help='suppress output, except fatal messages')

parser.add_argument('--print-bind-config', action='store_true',
                    help='print necessary configuration of BIND to use the generated file')

parser.add_argument('--reload-zone', action='store_true', help='trigger a reload of the zone after update')

args = parser.parse_args()

zonefile = args.zonefile
origin = args.origin

if args.verbose:
    set_log_level(args.verbose)
elif args.quiet:
    quiet_mode()
else:
    set_log_level(1)

if args.print_bind_config:
    print_usage(zonefile, origin)

zone = create_header_for_zonefile(origin)

domains = parse_lists(origin)

zone.to_file(zonefile)

with Path(zonefile).open('a') as f:
    for d in (sorted(domains)):
        f.write(d + ' IN CNAME drop.sinkhole.\n')
        if config['wildcard_block']:
            f.write('*.' + d + ' IN CNAME drop.sinkhole.\n')

logger.info('Zonefile generation complete')

if args.reload_zone:
    logger.debug(f'''Reload of zone will be done now''')
    reload_zone(origin)
