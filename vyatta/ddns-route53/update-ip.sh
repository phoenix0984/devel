#!/bin/bash
# This script updates a specific domain name in route53. It is designed to be
# run via crontab. This script will not push changes unless
# there is a change in the IP.
#
# Copyright 2018 by phoenix0984
#
# This program is released under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This script heavily depends on the work of Michael Kelly (michael@michaelkelly.org)
# All kudos to him. Go and visit his repo here: https://github.com/mjkelly/experiments
#
# Wed Nov 07 11:22:03 CET

# ======================================================================= #

domain="changeme"
host="changeme"
ttl="changeme"
zone_id="changeme"
key_id="changeme"
key_secret="changeme"

# ======================================================================= #

if [[ $(dpkg-query -W -f='${Status}' dnsutils 2>/dev/null | grep -c "ok installed") -eq 0 ]]; then
  logger -s "Package dnsutils not installed. Quitting."
  exit 0
fi

# Get the current IP address via OpenDNS Service. This is a more lightweight approach
# but in very restricted networks this may not work. Use the curl method in those cases.
#ip_server="http://api.ipify.org"
#current_ip="$(curl -s ${ip_server})" # or use static Interface address: "iface"

current_ip=$(dig +short myip.opendns.com @resolver1.opendns.com)

# Get currently valid ip & ttl of RRset
fqdn="${host}.${domain}."

# Use authoritative nameserver from SOA RR
dns_ns=$(dig +short SOA "${domain}" | awk '{print $1}')

# Get the actual RRset from NS
rrset_noall=$(dig +nocmd +noall +answer @"${dns_ns}" "${fqdn}")
rrset=$(dig +norecurse @"${dns_ns}" "${fqdn}")
rrset_ttl=$(awk '{print $2}' <<< "${rrset_noall}")
rrset_ip=$(awk '{print $5}' <<< "${rrset_noall}")

# Check if either one of IP or TTL changed:
if [[ "${current_ip}" = "${rrset_ip}" ]] && [[ "${ttl}" = "${rrset_ttl}" ]]; then
  logger -s "Old IP "${rrset_ip}" and TTL "${rrset_ttl}" did not change. Quitting."
  exit 0
fi

# ======================================================================= #

smtp_server="changeme"
smtp_port="changeme"
use_starttls="changeme"
from_addr="changeme"
from_pass="changeme"
to_addr="changeme"
cc_addr="changeme"
msg_subj="Update received: "${fqdn}" updated to "${current_ip}" TTL: "${ttl}""
msg_body="${rrset}"

# ======================================================================= #

update_cmd="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )/route53-ddns.py"

${update_cmd} \
  --domain="${fqdn}" \
  --zone-id="${zone_id}" \
  --amz-key-id="${key_id}" \
  --amz-key-secret="${key_secret}" \
  --ip="${current_ip}" \
  --ttl="${ttl}"\
  --dns_ttl="${rrset_ttl}"\
  --dns_ip="${rrset_ip}"\
  --smtp_server="${smtp_server}"\
  --smtp_port="${smtp_port}"\
  --starttls="${use_starttls}"\
  --from_addr="${from_addr}"\
  --from_pass="${from_pass}"\
  --to_addr="${to_addr}"\
  --cc_addr="${cc_addr}"\
  --msg_subj="${msg_subj}"\
  --msg_body="${msg_body}"\
  --syslog
exit $?