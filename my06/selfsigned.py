#!/usr/bin/env python

import argparse, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# took 7.5 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='generate self-signed X.509 CA certificate', add_help=False)
parser.add_argument("private_key_file", help="Private key file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store self-signed CA certificate (PEM form)")
args = parser.parse_args()

def lookup(h):
    if h == '0':
        return '0000'
    elif h == '1':
        return '0001'
    elif h == '2':
        return '0010'
    elif h == '3':
        return '0011'
    elif h == '4':
        return '0100'
    elif h == '5':
        return '0101'
    elif h == '6':
        return '0110'
    elif h == '7':
        return '0111'
    elif h == '8':
        return '1000'
    elif h == '9':
        return '1001'
    elif h == 'a' or h == 'A':
        return '1010'
    elif h == 'b' or h == 'B':
        return '1011'
    elif h == 'c' or h == 'C':
        return '1100'
    elif h == 'd' or h == 'D':
        return '1101'
    elif h == 'e' or h == 'E':
        return '1110'
    elif h == 'f' or h == 'F':
        return '1111'

def bitstr_to_int(bitstr):
    i=0
    for bit in bitstr:
        i<<=1
        if bit=='1':
            i|= 1
    
    return i

def int_to_bytestring(i, length):
    # converts integer to bytestring
    s = ""
    for smth in xrange(length):
        s = chr(i & 0xff) + s
        i >>= 8
    return s

def int_to_bytestring2(i):
    # converts integer to bytestring
    s = ""
    while(True):
        if i<=0: break
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

def asn1_len(content_str):
    length_bytes = int_to_bytestring2(len(content_str)) or "\x00"

    if len(content_str) < 128:
        return length_bytes

    return chr(0b10000000 | len(length_bytes)) + length_bytes

def asn1_null():
    # returns DER encoding of NULL
    return chr(0x05) + chr(0x00)

def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    t = chr(0x06)
    length = 1
    first_octet = 40 * oid[0] + oid[1]
    oid = oid[2:len(oid)]
    content = ''
    for i in range(0,len(oid)):
        subcontent = ''
        value = oid[i]
        masked = value & 0b1111111
        masked = masked & 0b01111111
        length = length + 1
        value = value >> 7
        subcontent = chr(masked) + subcontent
        while True:
            if value == 0:
                content = content + subcontent
                break
            else:
                masked = value & 0b1111111
                masked = masked | 0b10000000
                length = length + 1
                subcontent = chr(masked) + subcontent
                value = value >> 7
    return t+chr(length)+chr(first_octet)+content

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., "abc\x01")
    # returns DER encoding of OCTETSTRING
    return chr(0x04)+asn1_len(octets)+octets

def asn1_sequence(der):
    # der - DER bytestring to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return chr(0x30)+asn1_len(der)+der

def asn1_boolean(bool):
    # BOOLEAN encoder has been implemented for you
    if bool:
        bool = chr(0xff)
    else:
        bool = chr(0x00)
    return chr(0x01) + chr(0x01) + bool

def asn1_integer(i):
    s = int_to_bytestring2(i) or "\x00"

    # checking if the most significant bit of the most significant (left-most) byte is 1
    if ord(s[0]) & 0b10000000 == 0b10000000:
        s = "\x00" + s

    return chr(0b00000010) + asn1_len(s) + s

def asn1_set(der):
    # der - DER bytestring to encapsulate into set
    # returns DER encoding of SET
    return chr(0x31)+asn1_len(der)+der

def asn1_printablestring(string):
    # string - bytestring containing printable characters (e.g., "foo")
    # returns DER encoding of PrintableString
    return chr(0x13)+asn1_len(string)+string

def asn1_utctime(time):
    # time - bytestring containing timestamp in UTCTime format (e.g., "121229010100Z")
    # returns DER encoding of UTCTime
    return chr(0x17)+asn1_len(time)+time

def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type
    t = 0b10100000 | tag
    return chr(t)+asn1_len(der)+der

def int_to_bytestring_len(i, length):
    s = ""
    for _ in xrange(length):
        s = chr(i & 0b11111111) + s
        i = i >> 8
    return s

def asn1_bitstring(bitstr):
    pad_len = 8 - len(bitstr) % 8

    if pad_len == 8:
        pad_len = 0

    # padding the bitstring
    bitstr+= "0"*pad_len

    # converting bitstring to int
    i = 0
    for bit in bitstr:
        i = i << 1
        if bit=='1':
            i = i | 1

    length_in_bytes = (len(bitstr)+7) / 8
    s = chr(pad_len) + int_to_bytestring_len(i, length_in_bytes)
    return chr(0b00000011) + asn1_len(s) + s

def asn1_bitstring2(bytestr):
    encoded = bytestr.encode('hex')
    bitstr = ''
    for c in encoded:
        bitstr = bitstr + lookup(c)
    return asn1_bitstring(bitstr)

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    pem = content.split("\n")
    if content.startswith('----'):
        return ("".join(pem[1:(len(pem)-2)])).decode('base64')
    else:
        return content

def get_pubkey(filename):
    # reads public key file and returns (n, e)
    content = open(filename).read()
    content = pem_to_der(content)
    decoded = decoder.decode(content)
    bitstr = str(decoded[0][1])
    content = int_to_bytestring(bitstr_to_int(bitstr))
    pubkey = decoder.decode(content)[0]
    return int(pubkey[0]), int(pubkey[1])

def get_privkey(filename):
    # reads private key file and returns (n, d)
    content = open(filename).read()
    content = pem_to_der(content)
    privkey = decoder.decode(content)
    return int(privkey[0][1]), int(privkey[0][3])

def get_privkey2(filename):
    # reads private key file and returns (n, e)
    content = open(filename).read()
    content = pem_to_der(content)
    privkey = decoder.decode(content)
    return int(privkey[0][1]), int(privkey[0][2])

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5

    # calculate byte size of modulus n
    bytesize_n = len(int_to_bytestring2(n))
    
    # plaintext must be at least 3 bytes smaller than modulus
    if bytesize_n - len(plaintext) < 3:
        print("HALT!")
        sys.exit(1)

    numberToPad = bytesize_n - len(plaintext) - 3
    # generate padding bytes
    return chr(0x00) + chr(0x01) + chr(0xff)*numberToPad + chr(0x00) + plaintext

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    loc = plaintext.find('\x00',1)
    return plaintext[(loc+1):]


def digestinfo_der(m):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of m
    hasher = hashlib.sha256()
    hasher.update(m)
    digest_message = hasher.digest()
    der = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier([2,16,840,1,101,3,4,2,1]) +
            asn1_null()
        ) +
        asn1_octetstring(digest_message)
    )
    return der

def sign(m, keyfile):
    # sign DigestInfo of message m
    digestInfo = digestinfo_der(m)
    n,d = get_privkey(keyfile)
    padded_text = pkcsv15pad_sign(digestInfo,n)
    m = bytestring_to_int(padded_text)
    s = pow(m,d,n)
    bytesize_n = len(int_to_bytestring2(n))
    return int_to_bytestring(s,bytesize_n)

def selfsigned(privkey, certfile):
    # create x509v3 self-signed CA root certificate


    # get public key (n, e) from private key file
    n, e = get_privkey2(privkey)
    # construct subjectPublicKeyInfo from public key values (n, e)
    subjectPublicKeyInfo = asn1_sequence(
            asn1_sequence(
                asn1_objectidentifier([1,2,840,113549,1,1,1])+
                asn1_null()
            ) +
            asn1_bitstring2(
                asn1_sequence(
                    asn1_integer(n) +
                    asn1_integer(e)
                )
            )
        )
    # construct tbsCertificate structure
    tbsCertificate = asn1_sequence(
            asn1_tag_explicit(asn1_integer(2), 0) +
            asn1_integer(1) +
            asn1_sequence(
                asn1_objectidentifier([1,2,840,113549,1,1,11]) +
                asn1_null()
            ) +
            asn1_sequence(
                asn1_set(
                    asn1_sequence(
                        asn1_objectidentifier([2,5,4,6]) +
                        asn1_printablestring("EE")
                    ) +
                    asn1_sequence(
                        asn1_objectidentifier([2,5,4,10]) +
                        asn1_printablestring("University of Tartu")
                    ) +
                    asn1_sequence(
                        asn1_objectidentifier([2,5,4,3]) +
                        asn1_printablestring("DenizalpB79611")
                    )
                )
            ) +
            asn1_sequence(
                asn1_utctime("180322000001Z")+
                asn1_utctime("190322235959Z")
            ) +
            asn1_sequence(
                asn1_set(
                    asn1_sequence(
                        asn1_objectidentifier([2,5,4,6]) +
                        asn1_printablestring("EE")
                    ) +
                    asn1_sequence(
                        asn1_objectidentifier([2,5,4,10]) +
                        asn1_printablestring("University of Tartu")
                    ) +
                    asn1_sequence(
                        asn1_objectidentifier([2,5,4,3]) +
                        asn1_printablestring("DenizalpB79611")
                    )
                )
            ) +
            subjectPublicKeyInfo +
            asn1_tag_explicit(asn1_sequence(
                asn1_sequence(
                    asn1_objectidentifier([2,5,29,19]) +
                    asn1_boolean(True) +
                    asn1_octetstring(asn1_sequence(asn1_boolean(True)))
                ) +
                asn1_sequence(
                    asn1_objectidentifier([2,5,29,15]) +
                    asn1_boolean(True) +
                    asn1_octetstring(asn1_bitstring('0000011')) 
                )
            ),3)
        )
    # sign tbsCertificate structure
    signed = sign(tbsCertificate,privkey)

    # construct final X.509 DER
    final = asn1_sequence(
        tbsCertificate +
        asn1_sequence(
                asn1_objectidentifier([1,2,840,113549,1,1,11]) +
                asn1_null()
            ) +
        asn1_bitstring2(signed)
    )
    # convert to PEM by .encode('base64') and adding PEM headers
    pem = "-----BEGIN CERTIFICATE-----\n" + final.encode('base64') + "-----END CERTIFICATE-----\n"

    # write PEM certificate to file
    open(certfile, 'w').write(pem)

selfsigned(args.private_key_file, args.output_cert_file)