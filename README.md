# BIND ad blocker

Fetch various blocklists and generate a BIND zone from them.

Configure BIND to return `NXDOMAIN` for ad and tracking domains to stop clients from contacting them.

Requires BIND 9.8 or newer for [RPZ](https://en.wikipedia.org/wiki/Response_policy_zone) support.

Uses the following sources:

* [Peter Lowe’s Ad and tracking server list](https://pgl.yoyo.org/adservers/)
* [Malware domains](http://www.malwaredomains.com/)
* [MVPS HOSTS](http://winhelp2002.mvps.org/)
* [Adaway default blocklist](https://adaway.org/)
* [Dan Pollock’s hosts file](http://someonewhocares.org/hosts/zero/)
* [StevenBlack Unified hosts file](https://github.com/StevenBlack/)
* [CAMELEON](http://sysctl.org/cameleon/)
* [ZeuS domain blocklist (Standard)](https://zeustracker.abuse.ch)
* [hpHosts Ad and Tracking servers only](https://hosts-file.net/)
* [OpenPhish](https://openphish.com)
* [CyberCrime Tracker](http://cybercrime-tracker.net)
* [Squidblacklist.org](http://www.squidblacklist.org)
* [Disconnect.me](https://disconnect.me/trackerprotection)
* [The Firebog](https://firebog.net/)
* [Joewein.de](http://www.joewein.net)
* [SANS ISC - Suspicious Domains Low Sensitivity](https://isc.sans.edu/suspicious_domains.html#lists)
* [QuidsUp](https://quidsup.net/)


## Setup
Copy the `update-zonefile.py` script to `/usr/local/bin`.
Copy the `update-blacklist-zonefile.service` and `update-blacklist-zonefile.timer` into `/etc/systemd/system`.
Afterwards execute
    
    systemctl enable update-blacklist-zonefile.service
    systemctl enable update-blacklist-zonefile.timer

and

    systemctl start update-blacklist-zonefile.service

### Python packages

* [requests](https://pypi.python.org/pypi/requests)
* [dnspython](https://pypi.python.org/pypi/dnspython)

These packages need to be installed to run the update script.


## Usage
Useage of the 'update-zonefile.py' script

    usage: update-zonefile.py [-h] [-v | -q] [--print-bind-config] [--reload-zone]
                          zonefile origin

    positional arguments:
      zonefile             name of the generated file
      origin               name of the zone
    
    optional arguments:
      -h, --help           show this help message and exit
      -v, --verbose        increase verbosity (specify multiple times for more
                           output)
      -q, --quiet          suppress output, except fatal messages
      --print-bind-config  print necessary configuration of BIND to use the
                           generated file
      --reload-zone        trigger a reload of the zone after update


Example: `update-zonefile.py /var/bind/rpz/blacklist.zone rpz.blacklist -q --reload-zone`

`update-zonefile.py` will update the zone file with the fetched adserver lists and issue a `rndc reload origin` afterwards.

