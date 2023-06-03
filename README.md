> **⚠️ Archived — no longer maintained.**
> I no longer use BIND for DNS-level filtering, so this project has been
> retired. The script is kept here for reference and may become outdated as
> BIND, RPZ behaviour, and the upstream blocklists evolve. Use at your own
> risk.

---

# BIND ad blocker

Fetch various blocklists and generate a BIND zone from them.

Configure BIND to return `NXDOMAIN` for ad and tracking domains to stop clients from contacting them.

Requires BIND 9.8 or newer for [RPZ](https://en.wikipedia.org/wiki/Response_policy_zone) support.

The sources can be configured with the blocklists.conf file

## Setup
Copy the `update-blacklist-zonefile` script to `/usr/local/bin`.
Copy the `update-blacklist-zonefile.service` and `update-blacklist-zonefile.timer` into `/etc/systemd/system`.

Afterwards execute
```shell script
systemctl enable update-blacklist-zonefile.service
systemctl enable update-blacklist-zonefile.timer
```
and
```shell script
systemctl start update-blacklist-zonefile.service
```

### Required Python packages

* [requests](https://pypi.python.org/pypi/requests)
* [dnspython](https://pypi.python.org/pypi/dnspython)
* [jinja2](https://pypi.org/project/Jinja2/)
* [python-dateutil](https://pypi.org/project/python-dateutil/)

These packages need to be installed to run the update script.


## Usage
Usage of the `update-blacklist-zonefile` script
```text
usage: update-blacklist-zonefile [-h] [-v | -q] [--print-bind-config] [--reload-zone]
                      zonefile origin

positional arguments:
  zonefile             name of the generated file
  origin               name of the zone

optional arguments:
  -h, --help           show this help message and exit
  -v, --verbose        increase verbosity (specify multiple times for more output)
  -q, --quiet          suppress output, except fatal messages
  --print-bind-config  print necessary configuration of BIND to use the generated file
  --reload-zone        trigger a reload of the zone after update
```

Example: `update-blacklist-zonefile /var/bind/rpz/blacklist.zone rpz.blacklist -q --reload-zone`

`update-blacklist-zonefile` will update the zone file with the fetched server lists and issue a `rndc reload origin` afterwards.

