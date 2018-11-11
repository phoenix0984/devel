#!/usr/bin/python
# route53-ddns.py -- Updates a DNS record in Amazon's Route 53.
#
# See documentation here:
# http://docs.amazonwebservices.com/Route53/2012-02-29/DeveloperGuide/RESTRequests.html
#
# Copyright 2018 by phoenix0984
#
# This program is released under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# Special thanks go to Michael Kelly (https://github.com/mjkelly/experiments)

import sys
import re
import base64
import hashlib
import hmac
import httplib
import optparse
import socket
import syslog
import smtplib
import json
import time

from optparse import OptionParser
from xml.etree import ElementTree

parser = optparse.OptionParser()
parser.add_option('--amz-key-id', dest='key_id',
                  help='Amazon API key ID. Required.')
parser.add_option('--amz-key-secret', dest='key_secret',
                  help='Amazon API key secet value. Required.')
parser.add_option('--fqdn', dest='fqdn',
                  help='Fully qualified Domain name to update. Required.')
parser.add_option('--zone-id', dest='zone_id',
                  help='Amazon zone ID containing domain name. Required.')
parser.add_option('--ip', dest='ip',
                  help='New IPv4 for domain name.')
parser.add_option('--quiet', '-q', dest='quiet', default=False,
                  action="store_true",
                  help="Don't output to stdout unless there is an error.")
parser.add_option('--verbose', '-v', dest='verbose', default=False,
                  action="store_true",
                  help="Output more information.")
parser.add_option('--force', '-f', dest='force', default=False,
                  action="store_true",
                  help="Update the A record even if it has not changed.")
parser.add_option('--syslog', '-s', dest='syslog', default=False,
                  action="store_true",
                  help="Send output to syslog")
parser.add_option('--ttl', dest='ttl', default="3600",
                  help="Specify TTL Value for the RRset")
parser.add_option('--dns_ns', dest='dns_ns',
                  help="Specify authoritative Nameserver")
parser.add_option('--dns_ip', dest='dns_ip',
                  help="Specify old IP address of RRset")
parser.add_option('--dns_ttl', dest='dns_ttl',
                  help="Specify old TTL value of RRset")
parser.add_option('--webhook', dest='webhook',
                  help="Slack Webhook URL '/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'")
parser.add_option('--webhook_author', dest='webhook_author',
                  help="Slack Author to appear in the message")
opts, _ = parser.parse_args()

AMAZON_NS = 'https://route53.amazonaws.com/doc/2012-02-29/'

COMMENT_FORMAT = 'Automatic update from route53-update.py running on {hostname} at {time}'

# Format string for updating an A record, {name}, from {old_value} with
# {old_ttl} to {new_value} with {new_ttl}.
# See:
# http://docs.amazonwebservices.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
BODY_FORMAT = """<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2012-02-29/">
<ChangeBatch>
    <Comment>{comment}</Comment>
    <Changes>
      <Change>
          <Action>UPSERT</Action>
          <ResourceRecordSet>
            <Name>{name}</Name>
            <Type>A</Type>
            <TTL>{new_ttl}</TTL>
            <ResourceRecords>
                <ResourceRecord>
                  <Value>{new_value}</Value>
                </ResourceRecord>
            </ResourceRecords>
          </ResourceRecordSet>
      </Change>
    </Changes>
</ChangeBatch>
</ChangeResourceRecordSetsRequest>
"""


def usage():
    parser.print_help()
    sys.exit(2)


def log(msg):
    """Print unless we're in quiet mode.

    If syslog is enabled, print to standard out only if it is tty.
    """
    if not opts.quiet:
        if opts.syslog:
            syslog.syslog(syslog.LOG_NOTICE, msg)
        if not opts.syslog or sys.stdout.isatty():
            print (msg)


def vlog(msg):
    """Print if we're in verbose mode."""
    if opts.verbose:
        log(msg)


def get_time():
    """Gets the current time from amazon servers.

    Format is RFC 1123.
    http://docs.amazonwebservices.com/Route53/latest/DeveloperGuide/RESTAuthentication.html#StringToSign

    Returns:
        (date)
    """
    connection = httplib.HTTPSConnection('route53.amazonaws.com')
    connection.request('GET', '/date')
    response = connection.getresponse()
    return response.getheader('Date')


def make_auth(time_str, key_id, secret):
    """Creates an amazon authorization string.

    Format is specified here:
    http://docs.amazonwebservices.com/Route53/latest/DeveloperGuide/RESTAuthentication.html#AuthorizationHeader
    """
    h = hmac.new(secret, time_str, hashlib.sha256)
    h_b64 = base64.b64encode(h.digest())
    return 'AWS3-HTTPS AWSAccessKeyId=%s,Algorithm=HmacSHA256,Signature=%s' % (
        key_id, h_b64)


def qualify_path(path):
    return path.replace('/', '/{%s}' % AMAZON_NS)


def find_comment_in_response(response, required_comment):
    """Checks for a PENDING or INSYNC ChangeResponse with the given comment.

    Args:
        response: XML ChangeResourceRecordSetsResponse, as a string.
        required_comment: Comment string to look for.

    Returns:
        The ElementTree.Element the ChangeInfo with required_comment, or None if
        not found.
    """
    root = ElementTree.fromstring(response)
    info_path = './ChangeInfo'
    for node in root.findall(qualify_path(info_path)):
        comment = node.find(qualify_path('./Comment'))
        status = node.find(qualify_path('./Status'))
        if comment.text != required_comment:
            continue
        if status.text  not in ('PENDING', 'INSYNC'):
            vlog('Found unexpected status = %r' % status.text)
            return None
        return node
    vlog('Found no response for comment %r' % required_comment)
    return None


def upsert_rrset():
    vlog('Will set %r to %r with TTL of %r' % (fqdn, new_ip, new_ttl))

    auth = make_auth(time_str, key_id, secret)
    headers = {'X-Amz-Date': time_str, 'X-Amzn-Authorization': auth}

    # Path for GET request to list existing record only.
    get_rrset_path = '/2012-02-29/hostedzone/%s/rrset?name=%s&type=A&maxitems=1' % (zone_id, fqdn)

    # Path for POST request to update record.
    change_rrset_path = '/2012-02-29/hostedzone/%s/rrset' % zone_id

    connection = httplib.HTTPSConnection('route53.amazonaws.com')
    vlog('GET %s' % get_rrset_path)

    connection.request('GET', get_rrset_path, '', headers)
    response = connection.getresponse()
    response_txt = response.read()
    vlog('Response:\n%s' % response_txt)
    if dns_ip:
        log('Updating %s to %s TTL: %s (was %s TTL: %s)' % (fqdn, new_ip, new_ttl, dns_ip, dns_ttl))
    else:
        log('RRset does not exist. Creating RRset: %s   %s   IN   A   %s' % (fqdn, new_ttl, new_ip))

    connection = httplib.HTTPSConnection('route53.amazonaws.com')
    comment_str = COMMENT_FORMAT.format(hostname=socket.gethostname(),
                                        time=time_str)
    change_body = BODY_FORMAT.format(comment=comment_str,
                                    name=fqdn,
                                    new_value=new_ip,
                                    new_ttl=new_ttl)
    vlog('POST %s\n%s' % (change_rrset_path, change_body))

    connection.request('POST', change_rrset_path, change_body, headers)
    response = connection.getresponse()
    response_val = response.read()
    vlog('Response:\n%s' % response_val)

    if response.status != httplib.OK:
        raise RuntimeError('Address update returned non-OK repsonse: %s (not %s)' % (
            response.status, httplib.OK))
    if find_comment_in_response(response_val, comment_str) is None:
        raise RuntimeError(
            'Did not receive correct change response from Route 53. Response: %s',
            response_val)


def slack_webhook():
    slack_data = json.dumps({
        "attachments": [
            {
                "mrkdwn": "true",
                "author_name": "Route53 Robot",
                "author_link": "https://github.com/phoenix0984/devel",
                "fallback": "## DNS Update received\n",
                "pretext": "##### Route53 DynDNS activity #####",
                "title": "DNS Update pushed via " + dns_ns,
                "title_link" : "https://aws.amazon.com/route53/",
                "text": "*User:* " + fqdn.split('.')[0].title() +"\n*Old IP:* " + dns_ip + "\n*Current IP:* " + new_ip,
                "footer": "Slack API",
                "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                "ts": int(time.time()),
                "color": "#7CD197",
                # "actions": [
                #     {
                #         "type": "button",
                #         "text": ":pencil2: Get the code",
                #         "url": "https://github.com/phoenix0984"
                #     }
                # ]
            }
        ]
    }, indent=4)
    slack_headers = {'Content-Type': 'application/json', 'Accept': 'text/plain'}

    connection = httplib.HTTPSConnection('hooks.slack.com')
    connection.request('POST', webhook, slack_data, slack_headers)
    response = connection.getresponse()
    response_val = response.read()
    vlog('Response:\n%s' % response_val)

    if response.status != httplib.OK:
        raise RuntimeError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status, response.text)
        )


if __name__ == '__main__':
    # Define global variables
    fqdn           = opts.fqdn
    key_id         = opts.key_id
    secret         = opts.key_secret
    dns_ns         = opts.dns_ns
    dns_ip         = opts.dns_ip
    new_ip         = opts.ip
    zone_id        = opts.zone_id
    dns_ttl        = opts.dns_ttl
    new_ttl        = opts.ttl
    webhook        = opts.webhook
    webhook_author = opts.webhook_author

    time_str    = get_time()

    if opts.syslog:
        syslog.openlog('route53-ddns')

    if (not opts.key_id or not opts.key_secret or not opts.fqdn or
        not opts.zone_id or not opts.ip):
        print >>sys.stderr, ('--amz-key-id, --amz-key-secret, --fqdn, --zone-id, '
                            'and --ip are required.\n')
        usage()

    if opts.quiet and opts.verbose:
        print >>sys.stderr, '--quiet and --verbose are mutually exclusive.'
        usage()

    if not opts.fqdn.endswith('.'):
        print >>sys.stderr, '--fqdn should be fully-qualified and end with a dot.'
        usage()

    if (opts.ip == opts.dns_ip and opts.ttl == opts.dns_ttl):
        log('Old IP %s and TTL %s did not change. Quitting.' % (opts.dns_ip, opts.dns_ttl))
        sys.exit(0)
    try:
        upsert_rrset()
        slack_webhook()
    except Exception as e:
        print(e)
        sys.exit(1)