#!/usr/bin/env python

import sys     # do not use any other imports/libraries
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString, HexListToBinString

# took 3.0 hours (please specify here how much time your solution required)


# this will wait for card inserted in any reader
channel = CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
print "[+] Selected reader:", channel.getReader()

# using T=0 for compatibility (DigiID supports only T=0) and simplicity
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

# wrapper
def send(apdu):
    data, sw1, sw2 = channel.transmit(apdu)

    # success
    if [sw1,sw2] == [0x90,0x00]:
        return data
    # signals that there is more data to read
    elif sw1 == 0x61:
        return send([0x00, 0xC0, 0x00, 0x00, sw2]) # GET RESPONSE of sw2 bytes
    # probably error condition
    else:
        print "Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString(apdu))
        sys.exit()


# reading personal data file (EstEID spec page 23)

output = ''

table = {
1:'Surname',
2:'First name line 1',
3:'First name line 2',
4:'Sex',
5:'Nationality',
6:'Birth date',
7:'Personal identification code',
8:'Document number',
9:'Expiry date',
10:'Place of birth',
11:'Date of issuance',
12:'Type of residence permit',
13:'Notes line 1',
14:'Notes line 2',
15:'Notes line 3',
16:'Notes line 4',
}

# print all enteries in personal data file
send([0x00, 0xa4, 0x00, 0x0c])
send([0x00, 0xA4, 0x01, 0x0C] + [0x02, 0xEE, 0xEE])
send([0x00, 0xA4, 0x02, 0x0C, 0x02, 0x50, 0x44])

print("[+] Personal data file:")
#output = output + "[+] Personal data file:\n"
for i in range(16):
    record = send([0x00, 0xB2, (i+1), 0x04])
    print "\t["+str(i+1)+"]"+table[(i+1)]+":",HexListToBinString(record).decode("cp1252").encode("utf8")
   # output = output + "\t["+str(i+1)+"]"+table[(i+1)]+": "+HexListToBinString(record).decode("cp1252").encode("utf8")+"\n"


# reading pin retry counters in the card (EstEID spec page 26)
print("[+] PIN retry counters:")
#output = output + "[+] PIN retry counters:\n"
send([0x00, 0xa4, 0x00, 0x0c])
send([0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x16])

record = send([0x00, 0xB2, 0x01, 0x04])
print "\tPIN1:",record[5],"left"
#output = output + "\tPIN1: "+str(record[5])+" left\n"

record = send([0x00, 0xB2, 0x01, 0x04])
print "\tPIN2:",record[5],"left"
#output = output + "\tPIN2: "+str(record[5])+" left\n"

record = send([0x00, 0xB2, 0x01, 0x04])
print "\tPUK:",record[5],"left"
#output = output + "\tPUK: "+str(record[5])+" left\n"

# reading key usage counters in the card (EstEID spec page 31)
print "[+] Key usage counters:"
#output = output + "[+] Key usage counters:\n"

table = {
1:'signature key',
3:'authentication key',
}

send([0x00, 0xa4, 0x00, 0x0c])
send([0x00, 0xA4, 0x01, 0x0C] + [0x02, 0xEE, 0xEE])
send([0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x13])

def value(a,b,c):
    return (a << 16) | (b << 8) | c

record1 = send([0x00, 0xB2, 0x01, 0x04])
record2 = send([0x00, 0xB2, 0x03, 0x04])
print "\tsignature key:",(0xffffff - value(record1[12],record1[13],record1[14])),"times"
#output = output + "\tsignature key: "+str((0xffffff - value(record1[12],record1[13],record1[14])))+ " times\n"
print "\tauthentication key:",(0xffffff - value(record2[12],record2[13],record2[14])),"times"
#output = output + "\tauthentication key: "+str((0xffffff - value(record2[12],record2[13],record2[14])))+" times\n"

#open("esteid_info.out",'w').write(output)