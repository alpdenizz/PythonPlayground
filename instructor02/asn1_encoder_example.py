#!/usr/bin/env python
import sys

def int_to_bytestring(i):
    s = ""
    while i:
        s = chr(i & 0b11111111) + s
        i = i >> 8
    return s

def int_to_bytestring_len(i, length):
    s = ""
    for _ in xrange(length):
        s = chr(i & 0b11111111) + s
        i = i >> 8
    return s

def int_to_bytestring_7bit_byte(i):
    s = ""
    while i:
        s = chr(i & 0b01111111 | 0b10000000) + s
        i = i >> 7
    return s



def asn1_len(content_str):
    length_bytes = int_to_bytestring(len(content_str)) or "\x00"

    if len(content_str) < 128:
        return length_bytes

    return chr(0b10000000 | len(length_bytes)) + length_bytes

def asn1_integer(i):
    s = int_to_bytestring(i) or "\x00"

    # checking if the most significant bit of the most significant (left-most) byte is 1
    if ord(s[0]) & 0b10000000 == 0b10000000:
        s = "\x00" + s

    return chr(0b00000010) + asn1_len(s) + s

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

def asn1_objectidentifier(oid):

    s = chr(oid[0]*40+oid[1]) 

    for i in oid[2:]:
        comp = int_to_bytestring_7bit_byte(i)

        # right-most byte of the encoded OID component must have most significant bit 0
        s+= comp[:-1] + chr( ord(comp[-1]) ^ 0b10000000 )

    return chr(0b00000110) + asn1_len(s) + s
