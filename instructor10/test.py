#!/usr/bin/env python

import argparse, sys, os, datetime
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString, HexListToBinString

# parse arguments
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--keysize', required=True, type=int, default=None, choices=[1024,2048], help='Key size of RSA key')
args = parser.parse_args()


# this will wait for card inserted in any reader
channel = CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
print "[+] Selected reader:", channel.getReader()

# first try using T=0, then fallback to T=1
try:
    channel.connect(CardConnection.T0_protocol)
except:
    channel.connect(CardConnection.T1_protocol)

# detect and print EstEID card type (EstEID spec page 15)
atr = channel.getATR()
if atr == [0x3B,0xFE,0x94,0x00,0xFF,0x80,0xB1,0xFA,0x45,0x1F,0x03,0x45,0x73,0x74,0x45,0x49,0x44,0x20,0x76,0x65,0x72,0x20,0x31,0x2E,0x30,0x43]:
    print "[+] EstEID v1.0 on Micardo Public 2.1"
elif atr == [0x3B,0xDE,0x18,0xFF,0xC0,0x80,0xB1,0xFE,0x45,0x1F,0x03,0x45,0x73,0x74,0x45,0x49,0x44,0x20,0x76,0x65,0x72,0x20,0x31,0x2E,0x30,0x2B]:
    print "[+] EstEID v1.0 on Micardo Public 3.0 (2006)"
elif atr == [0x3B,0x6E,0x00,0x00,0x45,0x73,0x74,0x45,0x49,0x44,0x20,0x76,0x65,0x72,0x20,0x31,0x2E,0x30]:
    print "[+] EstEID v1.1 on MultiOS (DigiID)"
elif atr == [0x3B,0xFE,0x18,0x00,0x00,0x80,0x31,0xFE,0x45,0x45,0x73,0x74,0x45,0x49,0x44,0x20,0x76,0x65,0x72,0x20,0x31,0x2E,0x30,0xA8]:
    print "[+] EstEID v3.x on JavaCard"
elif atr == [0x3B,0xFA,0x18,0x00,0x00,0x80,0x31,0xFE,0x45,0xFE,0x65,0x49,0x44,0x20,0x2F,0x20,0x50,0x4B,0x49,0x03]:
    print "[+] EstEID v3.5 (10.2014) cold (eID)"
elif atr == [0x3B,0x6A,0x00,0x00,0x09,0x44,0x31,0x31,0x43,0x52,0x02,0x00,0x25,0xC3]:
    print "[+] Feitian FT-Java/D11CR"
else:
    print "[-] Unknown card:", toHexString(atr)

def send(apdu):
    data, sw1, sw2 = channel.transmit(apdu)

    # success
    if [sw1,sw2] == [0x90,0x00]:
        return data
    # T=0 signals that there is more data to read
    elif sw1 == 0x61:
	print "[=] More data to read:", sw2
        return send([0x00, 0xC0, 0x00, 0x00, sw2]) # GET RESPONSE of sw2 bytes
    # T=0 signals that incorrect Le specified - resend with correct Le
    elif sw1 == 0x6c:
	print "[=] Fixing Le=%s:" % (sw2)
        if len(apdu)==4 or (len(apdu) > 5 and apdu[4]==len(apdu)-5):
            apdu = apdu + [sw2]
        else:
            apdu = apdu[0:-1] + [sw2]
        return send(apdu)
    # probably error condition
    else:
        print "Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString(apdu))
        sys.exit()


# converts bytes (big endian) to integer
def bn(bytes):
        num = 0
        for byte in bytes:
                num <<= 8
                num |= ord(byte)
        return num

# converts integer to bytes (big endian)
def nb(i, length):
    bytes = ""
    for smth in xrange(length):
        bytes = chr(i & 0xff) + bytes
        i >>= 8
    return bytes

def now():
    return datetime.datetime.now()

def timediff(s):
    return (datetime.datetime.now()-s).total_seconds()

def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5

    # calculate byte size of modulus n
    k = (n.bit_length()+7)/8

    # plaintext must be at least 11 bytes smaller than modulus
    if len(plaintext) > (k - 11):
        print "[-] Plaintext larger than modulus - 11 bytes"
        sys.exit(1)

    # generate padding bytes
    padding_len = k - len(plaintext) - 3
    padding = ""
    for i in xrange(padding_len):
        padbyte = os.urandom(1)
        while padbyte=="\x00":
            padbyte = os.urandom(1)
        padding += padbyte

    return "\x00\x02" + padding + "\x00" + plaintext

def encrypt(n, e, m):
    m = pkcsv15pad_encrypt(m, n)
    m = bn(m)
    c = pow(m, e, n)
    c = nb(c, (n.bit_length()+7)/8)
    return c


print "[+] Generating %s-bit RSA key..." % (args.keysize)
s = now()
p1 = (args.keysize >> 8) & 0xff
p2 = args.keysize & 0xff
send([0x00, 0x02, p1, p2, 0x00])
print "[+] Key generated in %s seconds!" % (timediff(s))


print "[+] Retrieving public key..."
r = send([0x00, 0x06, 0x00, 0x00, 0x00])
n = bn(HexListToBinString(r))
print "[+] n=%s" % (n)
r = send([0x00, 0x04, 0x00, 0x00, 0x00])
e = bn(HexListToBinString(r))
print "[+] e=%s" % (e)


print "[?] Enter message to encrypt:",
m = raw_input()
c = encrypt(n, e, m)
print "[+] Encrypted message:", c.encode('hex')


print "[+] Sending ciphertext to card..."
p1 = ord(c[0])
p2 = ord(c[1])
c = c[2:]
s = now()
r = send([0x00, 0x08, p1, p2, len(c)] + [ord(byte) for byte in c]) # omit Le as a workaround for OMNIKEY 1021 and Feitian-D11CR T=0 bug
m_orig = HexListToBinString(r)
print "[+] Message decrypted in %s seconds!" % (timediff(s))
print "[+] Decrypted message:", m_orig
