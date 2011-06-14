#!/usr/bin/python
# vim:set et sw=4:
#
# certdata2pem.py - splits certdata.txt into multiple files
#
# Copyright (C) 2009 Philipp Kern <pkern@debian.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301,
# USA.

import base64
import os.path
import re
import sys
import textwrap

objects = []

# Dirty file parser.
in_data, in_multiline, in_obj = False, False, False
field, type, value, obj = None, None, None, dict()
for line in open('certdata.txt', 'r'):
    # Ignore the file header.
    if not in_data:
        if line.startswith('BEGINDATA'):
            in_data = True
        continue
    # Ignore comment lines.
    if line.startswith('#'):
        continue
    # Empty lines are significant if we are inside an object.
    if in_obj and len(line.strip()) == 0:
        objects.append(obj)
        obj = dict()
        in_obj = False
        continue
    if len(line.strip()) == 0:
        continue
    if in_multiline:
        if not line.startswith('END'):
            if type == 'MULTILINE_OCTAL':
                line = line.strip()
                for i in re.finditer(r'\\([0-3][0-7][0-7])', line):
                    value += chr(int(i.group(1), 8))
            else:
                value += line
            continue
        obj[field] = value
        in_multiline = False
        continue
    if line.startswith('CKA_CLASS'):
        in_obj = True
    line_parts = line.strip().split(' ', 2)
    if len(line_parts) > 2:
        field, type = line_parts[0:2]
        value = ' '.join(line_parts[2:])
    elif len(line_parts) == 2:
        field, type = line_parts
        value = None
    else:
        raise NotImplementedError, 'line_parts < 2 not supported.'
    if type == 'MULTILINE_OCTAL':
        in_multiline = True
        value = ""
        continue
    obj[field] = value
if len(obj.items()) > 0:
    objects.append(obj)

# Read blacklist.
blacklist = []
if os.path.exists('blacklist.txt'):
    for line in open('blacklist.txt', 'r'):
        line = line.strip()
        if line.startswith('#') or len(line) == 0:
            continue
        item = line.split('#', 1)[0].strip()
        blacklist.append(item)

# Build up trust database.
trust = dict()
trustmap = dict()
for obj in objects:

    if obj['CKA_CLASS'] != 'CKO_NSS_TRUST':
        continue
    if obj['CKA_LABEL'] in blacklist:
        print "Certificate %s blacklisted, ignoring." % obj['CKA_LABEL']
    elif obj['CKA_TRUST_SERVER_AUTH'] == 'CKT_NSS_TRUSTED_DELEGATOR':
        trust[obj['CKA_LABEL']] = True
    elif obj['CKA_TRUST_EMAIL_PROTECTION'] == 'CKT_NSS_TRUSTED_DELEGATOR':
        trust[obj['CKA_LABEL']] = True
    elif obj['CKA_TRUST_SERVER_AUTH'] == 'CKT_NETSCAPE_UNTRUSTED':
        print '!'*74
        print "UNTRUSTED BUT NOT BLACKLISTED CERTIFICATE FOUND: %s" % obj['CKA_LABEL']
        print '!'*74
        sys.exit(1)
    else:
        print "Ignoring certificate %s.  SAUTH=%s, EPROT=%s" % \
              (obj['CKA_LABEL'], obj['CKA_TRUST_SERVER_AUTH'],
               obj['CKA_TRUST_EMAIL_PROTECTION'])
    label = obj['CKA_LABEL']
    trustmap[label] = obj
    print " added cert", label

def label_to_filename(label):
    label = label.replace('/', '_')\
        .replace(' ', '_')\
        .replace('(', '=')\
        .replace(')', '=')\
        .replace(',', '_') + '.crt'
    return re.sub(r'\\x[0-9a-fA-F]{2}', lambda m:chr(int(m.group(0)[2:], 16)), label)

trust_types = {
  "CKA_TRUST_DIGITAL_SIGNATURE": "digital-signature",
  "CKA_TRUST_NON_REPUDIATION": "non-repudiation",
  "CKA_TRUST_KEY_ENCIPHERMENT": "key-encipherment",
  "CKA_TRUST_DATA_ENCIPHERMENT": "data-encipherment",
  "CKA_TRUST_KEY_AGREEMENT": "key-agreement",
  "CKA_TRUST_KEY_CERT_SIGN": "cert-sign",
  "CKA_TRUST_CRL_SIGN": "crl-sign",
  "CKA_TRUST_SERVER_AUTH": "server-auth",
  "CKA_TRUST_CLIENT_AUTH": "client-auth",
  "CKA_TRUST_CODE_SIGNING": "code-signing",
  "CKA_TRUST_EMAIL_PROTECTION": "email-protection",
  "CKA_TRUST_IPSEC_END_SYSTEM": "ipsec-end-system",
  "CKA_TRUST_IPSEC_TUNNEL": "ipsec-tunnel",
  "CKA_TRUST_IPSEC_USER": "ipsec-user",
  "CKA_TRUST_TIME_STAMPING": "time-stamping",
  "CKA_TRUST_STEP_UP_APPROVED": "step-up-approved",
}

openssl_trust = {
  "CKA_TRUST_SERVER_AUTH": "serverAuth",
  "CKA_TRUST_CLIENT_AUTH": "clientAuth",
  "CKA_TRUST_CODE_SIGNING": "codeSigning",
  "CKA_TRUST_EMAIL_PROTECTION": "emailProtection",
}

for obj in objects:
    if obj['CKA_CLASS'] == 'CKO_CERTIFICATE':
        #if not obj['CKA_LABEL'] in trust or not trust[obj['CKA_LABEL']]:
        #    continue
        fname = label_to_filename(obj['CKA_LABEL'][1:-1])
        f = open(fname, 'w')
        trustbits = []
        openssl_trustflags = []
        tobj = trustmap[obj['CKA_LABEL']]
        for t in trust_types.keys():
            if tobj.has_key(t) and tobj[t] == 'CKT_NSS_TRUSTED_DELEGATOR':
                trustbits.append(t)
                if t in openssl_trust:
                    openssl_trustflags.append(openssl_trust[t])
        f.write("# trust=" + " ".join(trustbits) + "\n")
        if openssl_trustflags:
            f.write("# openssl-trust=" + " ".join(openssl_trustflags) + "\n")
        f.write("-----BEGIN CERTIFICATE-----\n")
        f.write("\n".join(textwrap.wrap(base64.b64encode(obj['CKA_VALUE']), 64)))
        f.write("\n-----END CERTIFICATE-----\n")
