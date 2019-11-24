#!/usr/bin/env python

import argparse, hashlib, datetime, re, socket, sys, os, urlparse  # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder

# took x.y hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='Check certificates against CRL', add_help=False)
parser.add_argument("url", type=str, help="URL of CRL (DER)")
parser.add_argument("--issuer", required=True, metavar='issuer', type=str, help="CA certificate that has issued the certificates (DER/PEM)")
parser.add_argument("--certificates", required=True, metavar='cert', type=str, nargs='+', help="Certificates to check (DER/PEM)")
args = parser.parse_args()


def int_to_bytestring(i, length):
    # converts integer to bytestring
    s = ""
    for smth in xrange(length):
        s = chr(i & 0xff) + s
        i >>= 8
    return s

def bytestring_to_int(s):
    # converts bytestring to integer
    i = 0
    for char in s:
        i <<= 8
        i |= ord(char)
    return i

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == '--':
        content = content.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
        content = content.replace("-----END CERTIFICATE REQUEST-----", "")
        content = content.replace("-----BEGIN CERTIFICATE-----", "")
        content = content.replace("-----END CERTIFICATE-----", "")
        content = content.replace("-----BEGIN PUBLIC KEY-----", "")
        content = content.replace("-----END PUBLIC KEY-----", "")
        content = content.replace("-----BEGIN RSA PRIVATE KEY-----", "")
        content = content.replace("-----END RSA PRIVATE KEY-----", "")
        content = content.decode('base64')
    return content

def get_pubkey_certificate(filename):
    # reads certificate and returns (n, e) from subject public key

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    plaintext = plaintext[2:]
    if "\x00" in plaintext:
        return plaintext[plaintext.index("\x00")+1:]

def digestinfo_der(m, alg_oid):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA-X digest of m
    digest = ""
    hash_oid = []

    if alg_oid == [1,2,840,113549,1,1,5]:
        digest = hashlib.sha1(m).digest()
        hash_oid = [1,3,14,3,2,26]
    elif alg_oid == [1,2,840,113549,1,1,11]:
        digest = hashlib.sha256(m).digest()
        hash_oid = [2,16,840,1,101,3,4,2,1]
    elif alg_oid == [1,2,840,113549,1,1,12]:
        digest = hashlib.sha384(m).digest()
        hash_oid = [2,16,840,1,101,3,4,2,2]
    elif alg_oid == [1,2,840,113549,1,1,13]:
        digest = hashlib.sha512(m).digest()
        hash_oid = [2,16,840,1,101,3,4,2,3]
    else:
        print "[-] digestinfo_der(): unrecognized alg_oid:", alg_oid
        sys.exit(1)

    digestinfo = asn1_sequence( \
        asn1_sequence( \
                asn1_objectidentifier(hash_oid) + \
                asn1_null()) + \
        asn1_octetstring(digest))

    return digestinfo

def verify(certfile, c, contenttoverify, alg_oid):
    # returns 1 on "Verified OK" and 0 otherwise

    if digestinfo_from_signature == digestinfo_from_content:
        return 1
    return 0


# list of serial numbers to check
serials = []

# download CRL using python sockets
def download_crl(url):

    print "[+] Downloading", url

    # parsing url


    # get response header



    # get content-length value


    # receive CRL (get response body)

    return crl

# verify if the CRL is signed by the issuer and whether the CRL is fresh
def verify_crl(issuer, crl):

    if verify(issuer, signature, tbsCertList, alg_oid):
        print "[+] CRL signature check successful!"
    else:
        print "[-] CRL signature verification failed!"
        sys.exit(1)



    if now < thisUpdate or now > nextUpdate:
        print "[-] CRL outdated (nextUpdate: %s) (now: %s)" % (nextUpdate, now)
        sys.exit(1)


# verify if the certificates are signed by the issuer and add them to the list 'serials'
def load_serials(issuer, certificates):
    global serials

    for certificate in certificates:


        if verify(issuer, signature, tbsCertificate, alg_oid):
            print "[+] Serial %s (%s) loaded" % (serial, certificate)
            serials.append(serial)
        else:
            print "[-] Serial %s (%s) not loaded: not issued by CA" % (serial, certificate)


# check if the certificates are revoked
# if revoked -- print revocation date and reason (if available)
def check_revoked(crl):
    global serials

    CRLReason = {
	0: 'unspecified',
	1: 'keyCompromise',
	2: 'cACompromise',
	3: 'affiliationChanged',
	4: 'superseded',
	5: 'cessationOfOperation',
	6: 'certificateHold',
	8: 'removeFromCRL',
	9: 'privilegeWithdrawn',
	10: 'aACompromise',
	}

    # loop over revokedCerts
    for revokedCert in decoder.decode(crl)[0][0][5]:


        # if revoked serial is in our interest
        if serial in serials:


            # check if the extensions are present

                print "[-] Certificate %s revoked: %s %s" % (serial, revocationDate, reason)




# download CRL
crl = download_crl(args.url)

# verify CRL
verify_crl(args.issuer, crl)

# load serial numbers from valid certificates
load_serials(args.issuer, args.certificates)

# check revocation status
check_revoked(crl)
