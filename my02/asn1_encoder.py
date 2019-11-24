#!/usr/bin/env python
import sys   # do not use any other imports/libraries

# took 9.5 hours (please specify here how much time your solution required)

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

def asn1_boolean(bool):
    # BOOLEAN encoder has been implemented for you
    if bool:
        bool = chr(0xff)
    else:
        bool = chr(0x00)
    return chr(0x01) + chr(0x01) + bool

def asn1_null():
    # returns DER encoding of NULL
    return chr(0x05) + chr(0x00)

def int_to_bytestring(i):
    plain = ""
    bringer = 0b11111111
    msg_int = i
    masked = msg_int & bringer
    plain = chr(masked)

    while True:
        msg_int = msg_int >> 8
        if msg_int == 0: break
        else:
            masked = msg_int & bringer
            plain = plain + chr(masked)

    plain = plain[::-1]
    if ord(plain[0]) > 127:
        plain = chr(0x00) + plain
    return plain

def asn1_integer(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns DER encoding of INTEGER
    t = chr(0x02)
    if i <= 127:
        return t+chr(0x01)+chr(i)
    else:
        content = int_to_bytestring(i)
        return t+chr(len(content))+content

def asn1_bitstring(bitstr):
    # bitstr - bytestring containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    result = chr(0x03)
    if bitstr == "":
        return result + chr(0x01) + chr(0x00)
    else:
        remainder = len(bitstr) % 8
        div = len(bitstr) / 8
        padding = 0
        length = div + 1
        if remainder != 0:
            padding = 8-remainder
            length = length + 1
        add = "0"*padding
        bitstr = bitstr + add
        num_str = (ord(bitstr[0]) - ord("0"))
        bitstr = bitstr[1:len(bitstr)]
        for c in bitstr:
            num_str = num_str << 1
            num_str = num_str | (ord(c) - ord("0"))
        num = num_str
        octet = num & 0b11111111
        content = chr(octet)
        num = num >> 8
        while True:
            if num == 0: break
            octet = num & 0b11111111
            content = chr(octet) + content
            num = num >> 8
        return result+chr(length)+chr(padding)+content

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

# figure out what to put in '...' by looking on ASN.1 structure required (see slides)
asn1 = asn1_tag_explicit(
        asn1_sequence(
        asn1_set(
                asn1_integer(5) + 
                asn1_tag_explicit(asn1_integer(200),2) +
                asn1_tag_explicit(asn1_integer(65407),11)
                )
    +asn1_boolean(True)+asn1_bitstring("110")+
    asn1_octetstring("\x00\x01"+"\x02"*49)+
    asn1_null()+
    asn1_objectidentifier([1,2,840,113549,1])+
    asn1_printablestring("hello.")+
    asn1_utctime("150223010900Z")),0)

open(sys.argv[1], 'w').write(asn1)
