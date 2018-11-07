#!/usr/bin/python
# -----------------------------------------------------------------
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
# This script heavily depends on the work of Michael Kelly (michael@michaelkelly.org)
# All kudos to him. Go and visit his repo here: https://github.com/mjkelly/experiments
#
# Wed Nov 07 11:22:03 CET
# -----------------------------------------------------------------

from xml.etree import ElementTree
import base64
import hashlib
import hmac
import httplib
import optparse
import socket
import sys
import syslog

parser = optparse.OptionParser()
parser.add_option('--amz-key-id', dest='key_id',
                  help='Amazon API key ID. Required.')
parser.add_option('--amz-key-secret', dest='key_secret',
                  help='Amazon API key secet value. Required.')
parser.add_option('--domain', dest='domain',
                  help='Domain name to update (ending with a dot), or "auto" to '
                       'use the current hostname. Required.')
parser.add_option('--zone-id', dest='zone_id',
                  help='Amazon zone ID containing domain name. Required.')
parser.add_option('--ip', dest='ip', help='New IPv4 for domain name, '
                  '"iface" to attempt to auto-detect or '
                  '"nat" if the device is behind NAT.')
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
parser.add_option('--ttl', dest='ttl', default=3600,
                  help="Specify TTL Value for the RRset")
parser.add_option('--dns_ip', dest='dns_ip',
                  help="Specify old IP address of RRset")
parser.add_option('--dns_ttl', dest='dns_ttl',
                  help="Specify old TTL value of RRset")
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
      print msg

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
  vlog('Will set %r to %r with TTL of %r' % (domain, new_ip, new_ttl))

  auth = make_auth(time_str, key_id, secret)
  headers = {
    'X-Amz-Date': time_str,

    'X-Amzn-Authorization': auth,
  }
  # Path for GET request to list existing record only.
  get_rrset_path = '/2012-02-29/hostedzone/%s/rrset?name=%s&type=A&maxitems=1' % (zone_id, domain)
  # Path for POST request to update record.
  change_rrset_path = '/2012-02-29/hostedzone/%s/rrset' % zone_id

  connection = httplib.HTTPSConnection('route53.amazonaws.com')
  vlog('GET %s' % get_rrset_path)

  connection.request('GET', get_rrset_path, '', headers)
  response = connection.getresponse()
  response_txt = response.read()
  vlog('Response:\n%s' % response_txt)
  if dns_ip:
    log('Updating %s to %s TTL: %s (was %s TTL: %s)' % (domain, new_ip, new_ttl, dns_ip, dns_ttl))
  else:
    log('RRset does not exist. Creating RRset: %s   %s   IN   A   %s' % (domain, new_ttl, new_ip))

  connection = httplib.HTTPSConnection('route53.amazonaws.com')
  comment_str = COMMENT_FORMAT.format(hostname=socket.gethostname(),
                                    time=time_str)
  change_body = BODY_FORMAT.format(comment=comment_str,
                                   name=domain,
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
    sys.exit(0)

# ========== main ==========

if opts.syslog:
  syslog.openlog('route53-update')

if (not opts.key_id or not opts.key_secret or not opts.domain or
    not opts.zone_id or not opts.ip):
  print >>sys.stderr, ('--amz-key-id, --amz-key-secret, --domain, --zone-id, '
                       'and --ip are required.\n')
  usage()

if opts.quiet and opts.verbose:
  print >>sys.stderr, '--quiet and --verbose are mutually exclusive.'
  usage()

time_str = get_time()
key_id = opts.key_id
secret = opts.key_secret
zone_id = opts.zone_id
dns_ip = opts.dns_ip
dns_ttl = opts.dns_ttl

if opts.domain == "auto":
  domain = socket.gethostname() + '.'
else:
  domain = opts.domain

if opts.ip == "iface":
  new_ip = default_iface_ip
else:
  new_ip = opts.ip

if opts.ttl is None:
  new_ttl = "3600"
else:
  new_ttl = opts.ttl

if not domain.endswith('.'):
  print >>sys.stderr, '--domain should be fully-qualified, and end with a dot.'
  usage()

# Do the hard work
upsert_rrset()
