#!/usr/bin/env python

import hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# took 7.0 hours (please specify here how much time your solution required)

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

def bitstr_to_int(bitstr):
    i=0
    for bit in bitstr:
        i<<=1
        if bit=='1':
            i|= 1
    
    return i

def int_to_bytestring(i):
    # converts integer to bytestring
    s = ""
    while(True):
        if i<=0: break
        s = chr(i & 0xff) + s
        i >>= 8
    return s

def int_to_bytestring2(i, length):
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

def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5

    # calculate byte size of the modulus n
    bytesize_n = len(int_to_bytestring(n))

    # plaintext must be at least 11 bytes smaller than modulus
    if bytesize_n - len(plaintext) < 11:
        print("HALT!")
        sys.exit(1)

    # generate padding bytes
    numberToPad = bytesize_n - len(plaintext) - 3
    ps = os.urandom(numberToPad)
    for c in ps:
        if c == '\x00':
            new_c = os.urandom(1)
            while (new_c == '\x00'):
                new_c = os.urandom(1)
            ps = ps.replace(c,new_c,1)
    return chr(0x00) + chr(0x02) + ps + chr(0x00) + plaintext

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5

    # calculate byte size of modulus n
    bytesize_n = len(int_to_bytestring(n))
    
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

def encrypt(keyfile, plaintextfile, ciphertextfile):
    plaintext = open(plaintextfile).read()
    n,e = get_pubkey(keyfile)
    ptext = pkcsv15pad_encrypt(plaintext,n)
    m = bytestring_to_int(ptext)
    c = pow(m,e,n)
    bytesize_n = len(int_to_bytestring(n))
    open(ciphertextfile,'w').write(int_to_bytestring2(c,bytesize_n))
    pass

def decrypt(keyfile, ciphertextfile, plaintextfile):
    ciphertext = open(ciphertextfile).read()
    c = bytestring_to_int(ciphertext)
    n,d = get_privkey(keyfile)
    m = pow(c,d,n)
    bytesize_n = len(int_to_bytestring(n))
    message = int_to_bytestring2(m,bytesize_n)
    message = pkcsv15pad_remove(message)
    open(plaintextfile,'w').write(message)
    pass

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

def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    hasher = hashlib.sha256()
    file = open(filename)
    while True:
        read = file.read(512)
        if read == '': break
        hasher.update(read)
    digest_message = hasher.digest()
    der = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier([2,16,840,1,101,3,4,2,1]) +
            asn1_null()
        ) +
        asn1_octetstring(digest_message)
    )
    return der

def sign(keyfile, filetosign, signaturefile):
    plaintext = digestinfo_der(filetosign)
    n,d = get_privkey(keyfile)
    padded_text = pkcsv15pad_sign(plaintext,n)
    m = bytestring_to_int(padded_text)
    s = pow(m,d,n)
    bytesize_n = len(int_to_bytestring(n))
    open(signaturefile,'w').write(int_to_bytestring2(s,bytesize_n))
    # Warning: make sure that signaturefile produced has the same
    # byte size as the modulus (hint: use parametrized int_to_bytestring()).

def verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification Failure"
    signature = open(signaturefile).read()
    s = bytestring_to_int(signature)
    n,e = get_pubkey(keyfile)
    m = pow(s,e,n)
    bytesize_n = len(int_to_bytestring(n))
    message = int_to_bytestring2(m,bytesize_n)
    message = pkcsv15pad_remove(message)
    digestinfo_expected = message
    if digestinfo_expected == digestinfo_der(filetoverify):
        print("Verified OK")
    else:
        print("Verification Failure")

def usage():
    print "Usage:"
    print "encrypt <public key file> <plaintext file> <output ciphertext file>"
    print "decrypt <private key file> <ciphertext file> <output plaintext file>"
    print "sign <private key file> <file to sign> <signature output file>"
    print "verify <public key file> <signature file> <file to verify>"
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
