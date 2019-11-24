#!/usr/bin/env python

import argparse, sys     # do not use any other imports/libraries
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString, HexListToBinString

# took 4.0 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='Fetch certificates from ID card', add_help=False)
parser.add_argument('--cert', type=str, default=None, choices=['auth','sign'], help='Which certificate to fetch')
parser.add_argument("--out", required=True, type=str, help="File to store certifcate (PEM)")
args = parser.parse_args()


# this will wait for card inserted in any reader
channel = CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
print "[+] Selected reader:", channel.getReader()

# using T=0 for compatibility and simplicity
channel.connect(CardConnection.T0_protocol)

# detect and print EstEID card type (EstEID spec page 14)
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
else:
    print "[-] Unknown card:", toHexString(atr)
    sys.exit()

def certLen(firstTenBytes):
    lengthBytes = ''
    for i in range(1,10):
        if(firstTenBytes[i]=="\x30"):
            break
        else:
            lengthBytes = lengthBytes + firstTenBytes[i]
    howMany = ord(lengthBytes[0]) & 0b01111111
    length = 0
    for i in range(howMany):
        length = length << 8
        length = length | ord(lengthBytes[i+1])
    return length

def send(apdu):
    data, sw1, sw2 = channel.transmit(apdu)

    # success
    if [sw1,sw2] == [0x90,0x00]:
        return data
    # T=0 signals that there is more data to read
    elif sw1 == 0x61:
	print "[=] More data to read:", sw2
        return send([0x00, 0xC0, 0x00, 0x00, sw2]) # GET RESPONSE of sw2 bytes
    # probably error condition
    else:
        print "Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString(apdu))
        sys.exit()

# reading from card auth or sign certificate (EstEID spec page 33)
print "[=] Retrieving %s certificate..." % (args.cert)



# read first 10 bytes to parse ASN.1 length field and determine certificate length
send([0x00, 0xa4, 0x00, 0x0c])
send([0x00, 0xA4, 0x01, 0x0C] + [0x02, 0xEE, 0xEE])

if args.cert == "auth":
    #print("Auth mode")
    send([0x00, 0xA4, 0x02, 0x0C, 0x02, 0xAA, 0xCE])
elif args.cert == "sign":
    #print("Sign mode")
    send([0x00, 0xA4, 0x02, 0x0C, 0x02, 0xDD, 0xCE])

record = send([0x00, 0xB0, 0x00, 0x00, 0x0a])
firstTenBytes = toHexString(record).replace(" ","").decode('hex')
certlen = certLen(firstTenBytes)

print "[+] Certificate size: %d bytes" % (certlen)

# reading DER encoded certificate from smart card
start = firstTenBytes.find("\x30",1)
cert = firstTenBytes[0:start]

#for i in range(certlen):
#    msb = (i+start) >> 8
#    lsb = (i+start) & 0xff
#    add = send([0x00, 0xB0, msb, lsb, 0x01])
#    cert = cert + toHexString(add).decode('hex')

#print(len(cert))
#print(cert.encode('hex'))
#print(cert.encode('hex'))
msb = certlen >> 8
lsb = certlen & 0xff
begin = 0
for i in range(msb):
    begin = start + i * 0xff
    m = begin >> 8
    l = begin & 0xff
    add = send([0x00, 0xB0, m, l, 0xff])
    cert = cert + toHexString(add).replace(" ","").decode('hex')

begin = start + msb * 0xff
m = begin >> 8
l = begin & 0xff
add = send([0x00, 0xB0, m, l, lsb+msb])
cert = cert + toHexString(add).replace(" ","").decode('hex')

#print(len(cert))
#print(cert.encode('hex'))
# save certificate in PEM form
open(args.out,"wb").write("-----BEGIN CERTIFICATE-----\n"+cert.encode('base64')+"-----END CERTIFICATE-----\n")
print "[+] Certificate stored in", args.out
