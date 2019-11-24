#!/usr/bin/env python
import os, sys       # do not use any other imports/libraries
# took 2.5 hours (please specify here how much time your solution required)

def bytestring_to_int(s):
    # your implementation here
    msg = s
    head = msg[0]
    tail = msg[1:len(msg)]
    msg_int = ord(head)
    
    for c in tail:
        msg_int = msg_int << 8
        msg_int = msg_int | ord(c)
    
    return msg_int

def int_to_bytestring(i, length):
    # your implementation here
    plain = ""
    bringer = 0b11111111
    msg_int = i
    masked = msg_int & bringer
    plain = chr(masked)

    for r in range(0,length-1):
        msg_int = msg_int >> 8
        masked = msg_int & bringer
        plain = plain + chr(masked)

    plain = plain[::-1]
    return plain


def encrypt(pfile, kfile, cfile):
    # your implementation here
    plainFile = open(pfile).read()
    keyFile = os.urandom(len(plainFile))
    plain_int = bytestring_to_int(plainFile)
    key_int = bytestring_to_int(keyFile)
    cipher_int = plain_int ^ key_int
    cipher_text = int_to_bytestring(cipher_int, len(plainFile))
    open(cfile,"w").write(cipher_text)
    open(kfile,"w").write(keyFile)
    pass
    

def decrypt(cfile, kfile, pfile):
    # your implementation here
    cipherFile = open(cfile).read()
    keyFile = open(kfile).read()
    cipher_int = bytestring_to_int(cipherFile)
    key_int = bytestring_to_int(keyFile)
    plain_int = cipher_int ^ key_int
    plain_text = int_to_bytestring(plain_int, len(cipherFile))
    open(pfile,"w").write(plain_text)
    pass

def usage():
    print "Usage:"
    print "encrypt <plaintext file> <output key file> <ciphertext output file>"
    print "decrypt <ciphertext file> <key file> <plaintext output file>"
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
