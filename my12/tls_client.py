#!/usr/bin/python

import argparse, hmac, socket, sys, time, os, urlparse, datetime
from hashlib import sha1, sha256
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES # bonus
from pyasn1.codec.der import decoder  # do not use any other imports/libraries

# took 6.5 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == '--':
        content = content.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
        content = content.replace("-----END CERTIFICATE REQUEST-----", "")
        content = content.replace("-----BEGIN CERTIFICATE-----", "")
        content = content.replace("-----END CERTIFICATE-----", "")
        content = content.replace("-----BEGIN PUBLIC KEY-----", "")
        content = content.replace("-----END PUBLIC KEY-----", "")
        content = content.replace("-----BEGIN RSA PRIVATE KEY-----", "")
        content = content.replace("-----END RSA PRIVATE KEY-----", "")
        content = content.decode('base64')
    return content

def modify(str):
    str = str.replace("(","")
    str = str.replace(")","")
    str = str.replace(",","")
    str = str.replace(" ","")
    return str

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

def int_to_bytestring2(i):
    # converts integer to bytestring
    s = ""
    while(True):
        if i<=0: break
        s = chr(i & 0xff) + s
        i >>= 8
    return s

def bitstr_to_int(bitstr):
    i=0
    for bit in bitstr:
        i<<=1
        if bit=='1':
            i|= 1
    
    return i

def get_pubkey_certificate(cert):
    # reads the certificate and returns (n, e)
    cert = pem_to_der(cert)
    decoded = decoder.decode(cert)
    bitstr = modify(str(decoded[0][0][6][1]))
    content = int_to_bytestring2(bitstr_to_int(bitstr))
    pubkey = decoder.decode(content)[0]
    return int(pubkey[0]), int(pubkey[1])


def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5
    bytesize_n = len(int_to_bytestring2(n))

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

def rsa_encrypt(cert, m):
    # encrypts message m using public key from certificate cert
    n,e = get_pubkey_certificate(cert)
    ptext = pkcsv15pad_encrypt(m,n)
    m = bn(ptext)
    c = pow(m,e,n)
    bytesize_n = len(int_to_bytestring2(n))
    return nb(c,bytesize_n)

# converts bytes (big endian) to integer
def bn(bytes):
        num = 0
        for byte in bytes:
                num <<= 8
                num |= ord(byte)
        return num

# converts integer to bytes (big endian)
def nb(i, length=0):
    bytes = ""
    for smth in xrange(length):
        bytes = chr(i & 0xff) + bytes
        i >>= 8
    return bytes

# returns TLS record that contains client_hello handshake message
def client_hello():
    global client_random, handshake_messages

    print "--> client_hello()"

    # list of cipher suites the client supports
    csuite = "\x00\x05"	# TLS_RSA_WITH_RC4_128_SHA
    csuite+= "\x00\x2f" # TLS_RSA_WITH_AES_128_CBC_SHA
    #csuite+= "\x00\x35" # TLS_RSA_WITH_AES_256_CBC_SHA

    client_random = nb(int(time.time()),4) + os.urandom(28)
    # add handshake message header
    t = "\x01"
    b = "\x03\x03" + client_random + "\x00\x00" + "\x04" + csuite + "\x01\x00" 
    l = nb(len(b),3)
    message = t + l + b

    # add record layer header
    record = "\x16\x03\x03" + nb(len(message),2) + message
    handshake_messages += message

    return record

# returns TLS record that contains client_key_exchange message containing encrypted pre-master secret
def client_key_exchange():
    global server_cert, premaster, handshake_messages

    print "--> client_key_exchange()"
    premaster = "\x03\x03" + os.urandom(46)
    encrypted = rsa_encrypt(server_cert, premaster)
    body = nb(len(encrypted), 2) + encrypted
    message = nb(16, 1) + nb(len(body),3) + body
    record = "\x16\x03\x03" + nb(len(message),2) + message
    handshake_messages += message

    return record

# returns TLS record that contains change_cipher_spec message
def change_cipher_spec():
    print "--> change_cipher_spec()"
    record = nb(20,1) + "\x03\x03" + nb(1, 2) + "\x01"

    return record

# returns TLS record that contains encrypted finished handshake message
def finished():
    global handshake_messages, master_secret

    print "--> finished()"
    client_verify = PRF(master_secret, "client finished" + sha256(handshake_messages).digest(), 12)
    t = nb(20,1)
    l = nb(len(client_verify),3)
    message = t + l + client_verify
    handshake_messages += message

    m = encrypt(message, nb(22,1), "\x03\x03")
    record = "\x16\x03\x03" + nb(len(m),2) + m

    return record

# returns TLS record that contains encrypted application data
def application_data(data):
    print "--> application_data()"
    print data.strip()

    dataenc = encrypt(data, nb(23,1), "\x03\x03")

    record = nb(23,1) + "\x03\x03" + nb(len(dataenc),2) + dataenc

    return record

# parse TLS handshake messages
def parsehandshake(r):
    global server_hello_done_received, server_random, server_cert, handshake_messages, server_change_cipher_spec_received, server_finished_received, isRC4

    # decrypt if encryption enabled
    if server_change_cipher_spec_received:
        r = decrypt(r, "\x16", "\x03\x03")

    # read handshake message type and length from message header
    htype, hlength = r[0], bn(r[1:4])

    body = r[4:4+hlength]
    handshake = r[:4+hlength]
    handshake_messages+= handshake

    if htype == "\x02":
        print "	<--- server_hello()"
        server_random = body[2:34]
        timestamp = server_random[0:4]
        gmt = datetime.datetime.fromtimestamp(bn(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        sessionLength = bn(body[34:35])
        sessionEnd = 35+sessionLength
        sessid = body[35:sessionEnd]

        print "	[+] server randomness:", server_random.encode('hex').upper()
        print "	[+] server timestamp:", gmt
        print "	[+] TLS session ID:", sessid.encode('hex').upper()

        cipher = body[sessionEnd:(sessionEnd+2)]

        if cipher=="\x00\x2f":
            isRC4 = False
            print "	[+] Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA"
        elif cipher=="\x00\x35":
            print "	[+] Cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA"
        elif cipher=="\x00\x05":
            print "	[+] Cipher suite: TLS_RSA_WITH_RC4_128_SHA"
        else:
            print "[-] Unsupported cipher suite selected:", cipher.encode('hex')
            sys.exit(1)
        
        compression = r[(sessionEnd+4):(sessionEnd+5)]

        if compression!="\x00":
            print "[-] Wrong compression:", compression.encode('hex')
            sys.exit(1)
    
    elif htype == "\x0b":
        print "	<--- certificate()"
        certlen = bn(body[3:6])
        cert = body[6:(6+certlen)]
        pem = "-----BEGIN CERTIFICATE-----\n" + cert.encode('base64') + "-----END CERTIFICATE-----\n"
        print "\t[+] Server certificate length:", certlen
        server_cert = pem

    elif htype == "\x0e":
        print "	<--- server_hello_done()"
        server_hello_done_received = True
    
    elif htype == "\x14":
        print "	<--- finished()"
        server_finished_received = True
        # hashmac of all handshake messages except the current finished message (obviously)
        verify_data_calc = PRF(master_secret, "server finished" + sha256(handshake_messages[:-4-hlength]).digest(), 12)
        server_verify = body
        if server_verify!=verify_data_calc:
            print "[-] Server finished verification failed!"
            sys.exit(1)
    else:
        print "[-] Unknown Handshake Type:", htype.encode('hex')
        sys.exit(1)

    # handle the case of several handshake messages in one record
    leftover = r[4+len(body):]
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):
    global server_change_cipher_spec_received

    # read from TLS record header content type and length
    ctype = r[0]
    clength = bn(r[3:5])
    c = r[5:]

    # handle known types
    if ctype == "\x16":
        print "<--- handshake()"
        parsehandshake(c[:clength])
    elif ctype == "\x14":
        print "<--- change_cipher_spec()"
        server_change_cipher_spec_received = True
    elif ctype == "\x15":
        print "<--- alert()"
        level, desc = ord(c[0]), ord(c[1])
        if level == 1:
            print "	[-] warning:", desc
        elif level == 2:
            print "	[-] fatal:", desc
            sys.exit(1)
        else:
            sys.exit(1)
    elif ctype == "\x17":
        print "<--- application_data()"
        data = decrypt(c[:clength], "\x17", "\x03\x03")
        print data.strip()
    else:
        print "[-] Unknown TLS Record type:", ctype.encode('hex')
        sys.exit(1)

# PRF defined in TLS v1.2
def PRF(secret, seed, l):

    out = ""
    A = hmac.new(secret, seed, sha256).digest()
    while len(out) < l:
        out += hmac.new(secret, A + seed, sha256).digest()
        A = hmac.new(secret, A, sha256).digest()
    return out[:l]

# derives master_secret
def derive_master_secret():
    global premaster, master_secret, client_random, server_random
    master_secret = PRF(premaster, "master secret" + client_random + server_random, 48)

# derives keys for encryption and MAC
def derive_keys():
    global premaster, master_secret, client_random, server_random
    global client_mac_key, server_mac_key, client_enc_key, server_enc_key, rc4c, rc4s, iv_size

    key_block = PRF(master_secret, "key expansion" + server_random + client_random, 136)
    mac_size = 20
    key_size = 16
    iv_size = 16

    client_mac_key = key_block[:mac_size]
    server_mac_key = key_block[mac_size:mac_size*2]
    client_enc_key = key_block[mac_size*2:mac_size*2+key_size]
    server_enc_key = key_block[mac_size*2+key_size:mac_size*2+key_size*2]

    rc4c = ARC4.new(client_enc_key)
    rc4s = ARC4.new(server_enc_key)

# HMAC SHA1 wrapper
def HMAC_sha1(key, data):
    return hmac.new(key, data, sha1).digest()

# calculates MAC and encrypts plaintext
def encrypt(plain, type, version):
    global client_mac_key, client_enc_key, client_seq, rc4c, isRC4, cbcc, iv_size

    mac = HMAC_sha1(client_mac_key, nb(client_seq, 8) + type + version + nb(len(plain), 2) + plain)
    if isRC4:
        ciphertext = rc4c.encrypt(plain + mac)
        client_seq+= 1
        return ciphertext
    else:
        ivector = os.urandom(iv_size)
        cbcc = AES.new(client_enc_key, AES.MODE_CBC, ivector)
        padding = iv_size - ((len(plain + mac) + 1) % iv_size)
        print("Before encryption:",repr(plain+mac+nb(padding,1)*padding+nb(padding,1)))
        ciphertext = cbcc.encrypt(plain+mac+nb(padding,1)*padding+nb(padding,1))
        client_seq+= 1
        return ivector+ciphertext

# decrypts ciphertext and verifies MAC
def decrypt(ciphertext, type, version):
    global server_mac_key, server_enc_key, server_seq, rc4s, isRC4, cbcs, iv_size
    d = ""
    mac = ""
    plain = ""
    if isRC4:
        d = rc4s.decrypt(ciphertext)
        mac = d[-20:]
        plain = d[:-20]
    else:
        ivector = ciphertext[0:iv_size]
        ciphertext = ciphertext[iv_size:]
        cbcs = AES.new(server_enc_key, AES.MODE_CBC, ivector)
        d= cbcs.decrypt(ciphertext)
        remSize = bn(d[-1:])
        d = d[:-(remSize+1)]
        mac = d[-20:]
        plain = d[:-20]
    #mac = d[-20:]
    #plain = d[:-20]

    # verify MAC
    mac_calc = HMAC_sha1(server_mac_key, nb(server_seq, 8) + type + version + nb(len(plain), 2) + plain)
    if mac!=mac_calc:
        print "[-] MAC verification failed!"
        sys.exit(1)
    server_seq+= 1
    return plain

# read from the socket full TLS record
def readrecord():
    record = ""

    # read TLS record header (5 bytes)
    for _ in xrange(5):
        record += s.recv(1)

    # find data length
    datalen = bn(record[3:5])

    # read TLS record body
    for _ in xrange(datalen):
        record+= s.recv(1)

    return record

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
url = urlparse.urlparse(args.url)
host = url.netloc.split(':')
if len(host) > 1:
    port = int(host[1])
else:
    port = 443
host = host[0]


path = url.path

client_random = ""	# will hold client randomness
server_random = ""	# will hold server randomness
server_cert = ""	# will hold DER encoded server certificate
premaster = ""		# will hold 48 byte pre-master secret
master_secret = ""	# will hold master secret
handshake_messages = "" # will hold concatenation of handshake messages

# client/server keys and sequence numbers
client_mac_key = ""
server_mac_key = ""
client_enc_key = ""
server_enc_key = ""
client_seq = 0
server_seq = 0

# client/server RC4 instances
rc4c = ""
rc4s = ""

# client/server CBC instances
cbcc = ""
cbcs = ""

isRC4 = True

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
server_change_cipher_spec_received = False
server_finished_received = False

while not server_hello_done_received:
    parserecord(readrecord())

s.send(client_key_exchange())
s.send(change_cipher_spec())
derive_master_secret()
derive_keys()
s.send(finished())

while not server_finished_received:
    parserecord(readrecord())

s.send(application_data("GET / HTTP/1.0\r\n\r\n"))
parserecord(readrecord())

print "[+] Closing TCP connection!"
s.close()
