#!/usr/bin/python

import hashlib, sys
from pyasn1.codec.der import decoder
sys.path = sys.path[1:] # don't remove! otherwise the library import below will try to import your hmac.py 
import hmac # do not use any other imports/libraries

# took 2.5 hours (please specify here how much time your solution required)

###SHA256, MD5, SHA1
def verify(filename):
    print "[+] Reading HMAC DigestInfo from", filename+".hmac"
    der = open(filename+".hmac").read()
    toBeCalculated = open(filename)
    byte_chunk_size = 512
    identifier = str(decoder.decode(der)[0][0][0])
    digest = str(decoder.decode(der)[0][1])
    digest_calculated = None
    myHmac = None
    if identifier == "2.16.840.1.101.3.4.2.1":
        print("[+] "+"HMAC-SHA256 digest:"+(digest.encode('hex')))
        print "[?] Enter key:",
        key = raw_input()
        myHmac = hmac.new(key,None,hashlib.sha256)

    elif identifier == "1.3.14.3.2.26":
        print("[+] "+"HMAC-SHA1 digest:"+(digest.encode('hex')))
        print "[?] Enter key:",
        key = raw_input()
        myHmac = hmac.new(key,None,hashlib.sha1)

    elif identifier == "1.2.840.113549.2.5":
        print("[+] "+"HMAC-MD5 digest:"+(digest.encode('hex')))
        print "[?] Enter key:",
        key = raw_input()
        myHmac = hmac.new(key,None,hashlib.md5)

    while True:
        read = toBeCalculated.read(byte_chunk_size)
        if read == '': break
        myHmac.update(read)
    digest_calculated = myHmac.digest()
    
    if identifier == "2.16.840.1.101.3.4.2.1":
        print("[+] "+"Calculated HMAC-SHA256 digest:"+(digest_calculated.encode('hex')))
    elif identifier == "1.3.14.3.2.26":
        print("[+] "+"Calculated HMAC-SHA1 digest:"+(digest_calculated.encode('hex')))
    elif identifier == "1.2.840.113549.2.5":
        print("[+] "+"Calculated HMAC-MD5 digest:"+(digest_calculated.encode('hex')))

    if digest_calculated != digest:
        print "[-] Wrong key or message has been manipulated!"
    else:
        print "[+] HMAC verification successful!"

def asn1_null():
    # returns DER encoding of NULL
    return chr(0x05) + chr(0x00)

def asn1_len(content_str):
    # helper function - should be used in other functions to calculate length octet(s)
    # content - bytestring that contains TLV content octet(s)
    # returns length (L) octet(s) for TLV
    length = len(content_str)
    if (length <= 127):
        return chr(length)
    else:
        counter = 0
        content = ''
        while True:
            masked = length & 0b11111111
            content = chr(masked) + content
            length = length >> 8
            if length == 0:
                return chr(0x80 + counter + 1) + content
            else:
                counter = counter + 1

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., "abc\x01")
    # returns DER encoding of OCTETSTRING
    return chr(0x04)+asn1_len(octets)+octets

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

def asn1_sequence(der):
    # der - DER bytestring to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return chr(0x30)+asn1_len(der)+der

#HMAC-SHA256
def mac(filename):
    print "[?] Enter key:",
    key = raw_input()
    byte_chunk_size = 512
    myHmac = hmac.new(key,None,hashlib.sha256)
    file = open(filename)
    while True:
        read = file.read(byte_chunk_size)
        if read == '': break
        myHmac.update(read)
    digest_message = myHmac.digest()
    print("Calculated HMAC-SHA256: "+digest_message.encode('hex'))
    asn1 = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier([2,16,840,1,101,3,4,2,1]) +
            asn1_null()
        ) +
        asn1_octetstring(digest_message)
    )
    print "[+] Writing HMAC DigestInfo to", filename+".hmac"
    open(filename+".hmac",mode='w').write(asn1)


def usage():
    print "Usage:"
    print "-verify <filename>"
    print "-mac <filename>"
    sys.exit(1)

if len(sys.argv) != 3:
    usage()
elif sys.argv[1] == '-mac':
    mac(sys.argv[2])
elif sys.argv[1] == '-verify':
    verify(sys.argv[2])
else:
    usage()
