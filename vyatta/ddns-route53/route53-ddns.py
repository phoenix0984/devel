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
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.MIMEBase import MIMEBase
from email import encoders
import smtplib
import re
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
parser.add_option('--fqdn', dest='fqdn',
                  help='Fully qualified Domain name to update. Required.')
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
parser.add_option('--ttl', dest='ttl', default="3600",
                  help="Specify TTL Value for the RRset")
parser.add_option('--dns_ip', dest='dns_ip',
                  help="Specify old IP address of RRset")
parser.add_option('--dns_ttl', dest='dns_ttl',
                  help="Specify old TTL value of RRset")
parser.add_option('--smtp_server', dest='smtp_server',
                  help="Specify SMTP server")
parser.add_option('--smtp_port', dest='smtp_port', default="587",
                  help="Specify SMTP server port")
parser.add_option('--starttls', dest='starttls', default="True",
                  help="Use starttls as boolean")
parser.add_option('--from_addr', dest='from_addr',
                  help="Specify From address 'Your Name <from_addr@example.com>'")
parser.add_option('--from_pass', dest='from_pass',
                  help="Specify SMTP Login password")
parser.add_option('--to_addr', dest='to_addr',
                  help="Specify comma seperated list of recipients")
parser.add_option('--cc_addr', dest='cc_addr',
                  help="Specify comma seperated list of cc-recipients")
parser.add_option('--msg_subj', dest='msg_subj',
                  help="Specify the subject of the mail")
parser.add_option('--msg_body', dest='msg_body',
                  help="Specify the body of the mail")
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


def send_mail(smtp_server, smtp_port, from_addr,
              from_pass, to_addr, cc_addr, msg_subj, msg_body):
    """ Take arguments from calling bash script and send mail to recepients.

    """
    m = MIMEMultipart()

    m['From'] = from_addr
    m['To'] = to_addr
    m['Cc'] = cc_addr
    m['Subject'] = msg_subj

    body = msg_body

    m.attach(MIMEText(body, 'plain'))

    # Disable file attachements for now...
    #  file = "filename"
    #  fp = open("/path/to/file", "rb")

    #  p = MIMEBase('application', 'octet-stream')
    #  p.set_payload((fp).read())
    #  encoders.encode_base64(p)
    #  p.add_header('Content-Disposition', "attachment; filename= %s" % file)

    #  m.attach(p)

    # Convert the from address to a valid login literal
    rfc_from = re.search(r"\<(.*)\>", from_addr).group(1)

    s = smtplib.SMTP(smtp_server, smtp_port)
    if opts.starttls == "True":
        s.starttls()
    s.login(rfc_from, from_pass)
    s.sendmail(from_addr, to_addr.split(", ") + cc_addr.split(", "), m.as_string())
    s.quit()


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
    headers = {
        'X-Amz-Date': time_str,

        'X-Amzn-Authorization': auth,
    }
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
        sys.exit(0)


if __name__ == '__main__':
    # Define global variables
    smtp_server = opts.smtp_server
    smtp_port   = opts.smtp_port
    from_addr   = opts.from_addr
    from_pass   = opts.from_pass
    to_addr     = opts.to_addr
    cc_addr     = opts.cc_addr
    msg_subj    = opts.msg_subj
    msg_body    = opts.msg_body
    key_id      = opts.key_id
    secret      = opts.key_secret
    zone_id     = opts.zone_id
    fqdn        = opts.fqdn
    dns_ip      = opts.dns_ip
    new_ip      = opts.ip
    dns_ttl     = opts.dns_ttl
    new_ttl     = opts.ttl

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

    upsert_rrset()
    send_mail(smtp_server, smtp_port, from_addr,
              from_pass, to_addr, cc_addr, msg_subj, msg_body)
else:
    sys.exit(0)