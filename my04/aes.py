#!/usr/bin/python

import datetime, os, sys
from pyasn1.codec.der import decoder

# $ sudo apt-get install python-crypto
sys.path = sys.path[1:] # removes script directory from aes.py search path
from Crypto.Cipher import AES          # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html
from Crypto.Protocol.KDF import PBKDF2 # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Protocol.KDF-module.html#PBKDF2
from Crypto.Util.strxor import strxor  # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.strxor-module.html#strxor
import hashlib, hmac # do not use any other imports/libraries

# took 7.0 hours (please specify here how much time your solution required)


# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():

    # measure time for performing 10000 iterations
    salt = os.urandom(8)
    start = datetime.datetime.now()
    PBKDF2("passwd",salt,36,count=10000)
    stop = datetime.datetime.now()
    time = (stop-start).total_seconds()
    
    # extrapolate to 1 second
    iter = int(10000 / time)
    
    return iter # returns number of iterations that can be performed in 1 second

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


def encrypt(pfile, cfile):

    # benchmarking
    iter = benchmark()
    print "[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter)

    # asking for password
    print "[?] Enter password:",
    passwd = raw_input()

    # derieving key
    salt = os.urandom(8)
    #print("[+] Used Salt: "+salt.encode('hex'))
    pdbfk2 = PBKDF2(passwd,salt,36,iter)
    #print("[+] Used Iteration Number: "+str(iter))
    aes_key = pdbfk2[0:16]
    #print("[+] Used Aes_key: "+aes_key.encode('hex'))
    hmac_key = pdbfk2[16:36]
    #print("[+] Used Hmac_key: "+hmac_key.encode('hex'))
    myHmac = hmac.new(hmac_key,None,hashlib.sha1)

    # writing ciphertext in temporary file and calculating HMAC digest
    byte_chunk_size = 512
    iv = os.urandom(16)
    #print("[+] Used IV: "+iv.encode('hex'))
    iv_used = False
    cipher = AES.new(aes_key)
    file = open(pfile)
    enc = ''
    res = ''
    temp = open("temp",mode='w+')
    while True:
        chunk = file.read(byte_chunk_size)
        if chunk == '':
             break
        padding = 16 - (len(chunk) % 16)
        chunk = chunk + chr(padding)*padding
        block = chunk[0:16]
        
        if(not iv_used):
            res = strxor(block, iv)
            enc = cipher.encrypt(res)
            iv_used = True
        else:
            res = strxor(block,enc)
            enc = cipher.encrypt(res)

        temp.write(enc)

        remaining = chunk[16:len(chunk)]
        for i in range(0,(len(remaining)/16)):
            if remaining=='': 
                break
            res = strxor(remaining[0:16],enc)
            enc = cipher.encrypt(res)
            temp.write(enc)
            remaining = remaining[16:len(remaining)]
    
    ###DO digest of ciphertext not password!!!!
    temp.close()
    digest_input = ''
    temp_read = open("temp")
    while True:
        chunk = temp_read.read(byte_chunk_size)
        if chunk == '': 
            break
        digest_input += chunk
        myHmac.update(chunk)
    
    #print("[+] Digest Input: "+digest_input.encode('hex'))
    hmac_digest = myHmac.digest()
    #print("[+] Expected digest: "+hmac_digest.encode('hex'))

    # writing DER structure in cfile
    der_str = asn1_sequence(
        asn1_sequence(
            asn1_octetstring(salt)+
            asn1_integer(iter)+
            asn1_integer(36)
        )+
        asn1_sequence(
            asn1_objectidentifier([2,16,840,1,101,3,4,1,2])+
            asn1_octetstring(iv)
        )+
        asn1_sequence(
            asn1_sequence(
                asn1_objectidentifier([1,3,14,3,2,26]) +
                asn1_null()
            )+
            asn1_octetstring(hmac_digest)
      )
    )
    cipherfile = open(cfile,mode='w+')
    cipherfile.write(der_str)
    #print("[+] Generated DER: "+der_str.encode('hex'))

    # writing temporary ciphertext file to cfile
    temp = open("temp")
    while True:
        chunk = temp.read(byte_chunk_size)
        if chunk=='': 
            break
        cipherfile.write(chunk)

    cipherfile.close()
    test = open(cfile)
    # deleting temporary ciphertext file
    os.remove("temp")

    pass


def decrypt(cfile, pfile):

    # reading DER structure
    cipherfile = open(cfile).read(2)
    der_len = int(cipherfile[1].encode('hex'),16)
    #print("[+] Der length: "+str(der_len))
    file = open(cfile)
    der_str = file.read(der_len+2)
    decoded = decoder.decode(der_str)
    byte_chunk_size = 512

    salt = str(decoded[0][0][0])
    #print("[+] Obtained Salt: "+salt.encode('hex'))
    
    iter_n = int(str(decoded[0][0][1]))
    #print("[+] Obtained Iteration Number: "+str(iter_n))
    
    key_len = int(str(decoded[0][0][2]))
    #print("[+] Obtained Key Length: "+str(key_len))

    aes_id = str(decoded[0][1][0])
    aes_iv = str(decoded[0][1][1])
    #print("[+] Obtained IV: "+aes_iv.encode('hex'))

    hash_id = str(decoded[0][2][0][0])
    digest_expected = str(decoded[0][2][1])

    # asking for password
    print "[?] Enter password:",
    passwd = raw_input()

    # derieving key
    pdbfk2 = PBKDF2(passwd,salt,36,iter_n)
    aes_key = pdbfk2[0:16]
    #print("[+] Used AES key: "+aes_key.encode('hex'))
    hmac_key = pdbfk2[16:36]
    #print("[+] Used HMAC key: "+hmac_key.encode('hex'))
    myHmac = hmac.new(hmac_key,None,hashlib.sha1)
    
    readc = open(cfile)
    readc.read(der_len+2)
    digest_input = ''
    while True:
        chunk = readc.read(byte_chunk_size)
        if chunk == '':
            break
        digest_input += chunk
        myHmac.update(chunk)
    #print("[+] Digest Input: "+digest_input.encode('hex'))
    digest_produced = myHmac.digest()

    #print("[+] Digest produced: "+digest_produced.encode('hex'))
    # first pass over ciphertext to calculate and verify HMAC
    if digest_expected != digest_produced:
        print("[-] HMAC verification failure: wrong password or modified ciphertext!")
        return
    
    # second pass over ciphertext to decrypt
    byte_chunk_size = 512
    iv = aes_iv
    cipher = AES.new(aes_key)
    plaintext = ''
    dec = ''
    res = ''
    writep = open(pfile,'w')
    while True:
        chunk = file.read(byte_chunk_size)
        if chunk == '': break
        
        res = cipher.decrypt(chunk[0:16])
        dec = strxor(res,iv)
        plaintext = plaintext + dec
        iv = chunk[0:16]

        chunk = chunk[16:len(chunk)]
        for i in range(0,(len(chunk)/16)):
            res = cipher.decrypt(chunk[0:16])
            dec = strxor(res,iv)
            plaintext = plaintext + dec
            iv = chunk[0:16]
            chunk = chunk[16:len(chunk)]
    
    padding_len = int(plaintext[len(plaintext)-1].encode('hex'),16)
    plaintext = plaintext[0:(len(plaintext)-padding_len)]
    
    while True:
        if plaintext == '':
            break
        writep.write(plaintext[0:byte_chunk_size])
        plaintext = plaintext[byte_chunk_size:]
    
    pass

def usage():
    print "Usage:"
    print "-encrypt <plaintextfile> <ciphertextfile>"
    print "-decrypt <ciphertextfile> <plaintextfile>"
    sys.exit(1)


if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()
