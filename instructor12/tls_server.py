#!/usr/bin/python

import argparse, hmac, socket, sys, time, os, urlparse, datetime
from hashlib import sha1, sha256
from Crypto.Cipher import ARC4
from pyasn1.codec.der import decoder

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 server')
parser.add_argument('--port', default=443, type=int, help='Port to listen (default 443)')
parser.add_argument('--macfail', default=None, action="store_true", help='Use incorrect MAC for encryption')
parser.add_argument('--verifyfail', default=None, action="store_true", help='Return incorrect server_verify in finished message')
args = parser.parse_args()


cert_pem = """-----BEGIN CERTIFICATE-----
MIICJjCCAY+gAwIBAgIECA7v9TANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJFRTEcMBoGA1UE
ChMTVW5pdmVyc2l0eSBvZiBUYXJ0dTEPMA0GA1UECxMGSVQgZGVwMRcwFQYDVQQDEw5Bcm5pcyBS
b290IENBMjAeFw0xMjA4MjgxMjU5MzFaFw0xNTA4MjgxMjU5MzFaMB0xCzAJBgNVBAYTAkVFMQ4w
DAYDVQQDEwV1dC5lZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAuwatp/lNIpSqFdHWjJui
CA0eCcqKmGsrXKOt8SWTwJfP4ZQfkoIknEG/aZwoezQP7+OAxpJPPpB+RDvP0oXM+98qZkBOgL1Z
UPMkMcvXDWj3EryeUM8BmeVzgamZuF/E+F3GJuPtSGwrHgrHZfpYrWxY1Tpypj8/Hy11dLtky50C
AwEAAaM7MDkwDwYDVR0TAQH/BAUwAwEBADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYI
KwYBBQUHAwEwDQYJKoZIhvcNAQEFBQADgYEAFqe8yaMILDh7fSb0r7EyqjlUyN2iOFvKjmgT7XGd
Z7tmn0j90u7o1sF7mXecBtKFzTbGZqn99ZTIjxHTRTa5Wh84jsAFJPoJ3fG+75eyDjtzHebETEPg
iyK7W3HNSVrSi33OwSLuZ9YK2SY7VkfC0sqwh8Zs+z3ZoJJoWCEDu1s=
-----END CERTIFICATE-----"""

priv_pem = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC7Bq2n+U0ilKoV0daMm6IIDR4JyoqYaytco63xJZPAl8/hlB+S
giScQb9pnCh7NA/v44DGkk8+kH5EO8/Shcz73ypmQE6AvVlQ8yQxy9cNaPcSvJ5Q
zwGZ5XOBqZm4X8T4XcYm4+1IbCseCsdl+litbFjVOnKmPz8fLXV0u2TLnQIDAQAB
AoGANQOam/+l5sR/RfoaN/cxwdh+CEZ6bOQMAZGAD9gX/sLJsWa8YFo1qHlWmcgj
DXFfhx9U9HSqs9BfilXt/f3hcZPpdhhELaJTFUZlbDhGAqH8quQS0Yxqb+MIRQGL
8qQMbBexfF5s1Lq8y52cSlLeJqbDAFLOWuTG0w7PmkUrXCECQQDe61INzm0zdOwU
ziYSmcD16ekgfI5mQGJfj111o2jSLX+FDyAWG6QwcUZ80hFHQVfdPwYLp99BjjjH
wPXwWQWVAkEA1sfH+y6C0qgxTyIubVHRrdzEZVS2B/X6afS7ivH3ojhe+p7o7dsU
O7R2dycl8LJ3vFxXHbj2mclSP5RC+agb6QJBAJLFgZsRhRjSLPZt3Od2UHQZdKMt
H1z3m02ryS9BTizERCfJk6i6vloe2vgoH7Q4s686ZbKa7wXsrDnpNITxOBkCQDBi
mV6wv7ANS+5z2Nmv0PjF/0iEqO1qMJumEonesNbOtDbpjbfn3ssEgJufKiDrU6YP
d2Cuxn8mp2zDTcNIZ+ECQC3jHGQBEp7By/pBWm6rh94APxJScniYzBmp4P+rHeOH
vvmZO0/XKglAa1TtRTEgYBBxWueAEhUyk/3L8aRzzm4=
-----END RSA PRIVATE KEY-----"""

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

def get_privkey(key_pem):
    # reads private key and returns (n, d)
    privkey = pem_to_der(key_pem)
    privkey = decoder.decode(privkey)
    if str(privkey[0][0]) != '0':
        print "[-] Not a valid private key!"
        sys.exit(1)
    return int(privkey[0][1]), int(privkey[0][3])

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    if plaintext[:2]!="\x00\x02":
        print "[-] Wrong RSA encryption padding!"
        sys.exit(1)
    plaintext = plaintext[2:]
    plaintext = plaintext[plaintext.index("\x00")+1:]
    return plaintext

def rsa_decrypt(key_pem, ciphertext):
    n, d = get_privkey(key_pem)
    c = ciphertext
    c = bn(c)
    m = pow(c, d, n)
    m = nb(m, (n.bit_length()+7)/8)
    m = pkcsv15pad_remove(m)
    return m

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
    if length==0: length = (i.bit_length()+7)/8
    for smth in xrange(length):
        bytes = chr(i & 0xff) + bytes
        i >>= 8
    return bytes

# returns TLS record that contains server_hello handshake message
def server_hello():
    global server_random, handshake_messages

    print "--> server_hello()"

    body = "\x03\x03"	# version TLS v1.2
    server_random = nb(int(time.time()),4) + os.urandom(28)
    body+= server_random	# gmt_unix_time[4] + server_random[28]

    body+= "\x00"	# session_id_length
    body+= ""		# session_id

    # cipher suite selected
    csuite = "\x00\x05"	# TLS_RSA_WITH_RC4_128_SHA
    body+= csuite

    body+= "\x00"	# compression method: null

    print "	[+] server randomness:", server_random.encode('hex').upper()
    print "	[+] server timestamp:", datetime.datetime.fromtimestamp(bn(server_random[:4])).strftime('%Y-%m-%d %H:%M:%S')
    print "	[+] TLS session ID:"
    print "	[+] Cipher suite: TLS_RSA_WITH_RC4_128_SHA"

    # add handshake message header
    handshake = "\x02"	# msg_type=server_hello(2)
    handshake+= nb(len(body), 3) # length
    handshake+= body

    # add record layer header
    record = "\x16"	# handshake(22)
    record+= "\x03\x03"	# version TLS v1.2
    record+= nb(len(handshake), 2) # length
    record+= handshake
    handshake_messages+= handshake
    return record

# returns TLS record that contains certificate handshake message
def certificate():
    global handshake_messages, cert_pem 

    print "--> certificate()"

    cert_der = pem_to_der(cert_pem)
    print "	[+] Server certificate length:", len(cert_der)

    body = nb(len(cert_der), 3) + cert_der # certificate length
    body = nb(len(body), 3) + body # certificates length

    # add handshake message header
    handshake = "\x0b"	# msg_type=certificate(11)
    handshake+= nb(len(body), 3) # length
    handshake+= body

    # add record layer header
    record = "\x16"	# handshake(22)
    record+= "\x03\x03"	# version TLS v1.2
    record+= nb(len(handshake), 2) # length
    record+= handshake
    handshake_messages+= handshake
    return record

# returns TLS record that contains server_hello_done handshake message
def server_hello_done():
    global handshake_messages

    print "--> server_hello_done()"
    body = ""

    # add handshake message header
    handshake = "\x0e"	# msg_type=server_hello_done(14)
    handshake+= nb(len(body), 3) # length
    handshake+= body

    # add record layer header
    record = "\x16"	# handshake(22)
    record+= "\x03\x03"	# version TLS v1.2
    record+= nb(len(handshake), 2) # length
    record+= handshake
    handshake_messages+= handshake
    return record


# returns TLS record that contains change_cipher_spec message
def change_cipher_spec():
    print "--> change_cipher_spec()"
    changecipher = "\x01"
    record = "\x14"	# change_cipher_spec(20)
    record+= "\x03\x03"	# version TLS v1.2
    record+= nb(len(changecipher), 2)	# length
    record+= changecipher
    return record

# returns TLS record that contains encrypted finished handshake message
def finished():
    global handshake_messages
    global master_secret

    print "--> finished()"

    # simulate verify failure for client
    if args.verifyfail:
        server_verify = PRF(master_secret, "server finddddd" + sha256(handshake_messages).digest(), 12)
    else:
        server_verify = PRF(master_secret, "server finished" + sha256(handshake_messages).digest(), 12)

    handshake = "\x14"	# msg_type=finished(20)
    handshake+= nb(len(server_verify), 3) # length
    handshake+= server_verify

    enchandshake = encrypt(handshake, "\x16", "\x03\x03")
    record = "\x16"	# handshake(22)
    record+= "\x03\x03"	# version TLS v1.2
    record+= nb(len(enchandshake), 2) # length
    record+= enchandshake
    handshake_messages+= handshake
    return record

# returns TLS record that contains encrypted application data
def application_data(data):
    print "--> application_data()"
    print data.strip()
    cdata = encrypt(data, "\x17", "\x03\x03")
    record = "\x17"	# application_data(23)
    record+= "\x03\x03"	# version TLS v1.2
    record+= nb(len(cdata), 2) # length
    record+= cdata
    return record

# parse TLS handshake messages
def parsehandshake(r):
    global client_hello_received, client_random, handshake_messages, client_change_cipher_spec_received, client_finished_received
    global priv_pem, client_max_ver, premaster

    # decrypt if encryption enabled
    if client_change_cipher_spec_received:
        r = decrypt(r, "\x16", "\x03\x03")

    # read handshake message type and length from message header
    htype, hlength = r[0], bn(r[1:4])

    body = r[4:4+hlength]
    handshake = r[:4+hlength]
    handshake_messages+= handshake

    if htype == "\x01":
        print "	<--- client_hello()"
        version, client_random, sessid_len = body[:2], body[2:34], bn(body[34])
        offset = 35

        sessid = body[offset:offset+sessid_len]
        offset+= sessid_len

        print "	[+] version:", version.encode('hex').upper()
        client_max_ver = version
        if client_max_ver!="\x03\x03":
            print "[-] Unsupported version! Only TLS v1.2 is supported!"
            sys.exit(1)

        print "	[+] client randomness:", client_random.encode('hex').upper()
        gmt = datetime.datetime.fromtimestamp(bn(client_random[:4])).strftime('%Y-%m-%d %H:%M:%S')
        print "	[+] client timestamp:", gmt
        print "	[+] TLS session ID:", sessid.encode('hex').upper()

        cipher_table = {
            'c02b':'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'c02f':'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            '009e':'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
            '0005':'TLS_RSA_WITH_RC4_128_SHA',
            '0004':'TLS_RSA_WITH_RC4_128_MD5',
            '000a':'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
            '0035':'TLS_RSA_WITH_AES_256_CBC_SHA',
            '002f':'TLS_RSA_WITH_AES_128_CBC_SHA',
        }

        cipher_len = bn(body[offset:offset+2])
        offset+= 2
        print "	[+] Cipher suites:"
        supported_cipher = False
        for i in xrange(cipher_len/2):
            cipher = body[offset+i*2:offset+i*2+2].encode('hex')
            if cipher in cipher_table.keys():
                print "		", cipher_table[cipher]
            else:
                print "		", cipher
            if cipher == '0005':
                supported_cipher = True

        if not supported_cipher:
            print "[-] Only TLS_RSA_WITH_RC4_128_SHA supported!"
            sys.exit(1)

        offset+= cipher_len

        compress_len = bn(body[offset])
        offset+= compress_len

        compress_table = {
            '00':'null',
            '01':'deflate',
        }

        print "	[+] Compression methods:"
        for i in xrange(compress_len):
            compress = body[offset+i:offset+i+1].encode('hex')
            if compress in compress_table.keys():
                print "		", compress_table[compress]
            else:
                print "[-] Unknown compression method:", compress
                sys.exit(1)
        offset+= compress_len


        ext_len = bn(body[offset:offset+2])
        offset+= 2
        print "	[+] Extensions length:", ext_len
        offset+= ext_len
        client_hello_received = True
        
    elif htype == "\x10":
        print "	<--- client_key_exchange()"
        premaster_len = bn(body[0:2])
        print "	[+] PreMaster length:", premaster_len

        # check if RSA ciphertext the same size as modulus
        if premaster_len!=len(nb(get_privkey(priv_pem)[0])):
            print "[-] RSA ciphertext length (%s) not the same length as modulus (%s)!" % (premaster_len, len(nb(get_privkey(priv_pem)[0])))
            sys.exit(1)

        offset = 2
        premaster_enc = body[offset:offset+premaster_len]
        print "	[+] PreMaster (encrypted):", premaster_enc.encode('hex')
        premaster = rsa_decrypt(priv_pem, premaster_enc)
        print "	[+] PreMaster:", premaster.encode('hex')
        if not premaster.startswith(client_max_ver):
            print "[-] PreMaster must start with %s!" % (client_max_ver.encode('hex'))
            sys.exit(1)
        offset+= premaster_len

    elif htype == "\x14":
        print "	<--- finished()"
        client_finished_received = True
        # verify_data
        client_verify = r[4:]
        print "	[+] client_verify (received):", client_verify.encode('hex')
        verify_data_calc = PRF(master_secret, "client finished" + sha256(handshake_messages[:-4-hlength]).digest(), 12)
        print "	[+] client_verify (calculated):", verify_data_calc.encode('hex')
        if client_verify!=verify_data_calc:
            print "[-] Client's finished verification failed!"
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
    global client_change_cipher_spec_received

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
        client_change_cipher_spec_received = True
        if c != "\x01":
            print "[-] Bad ChangeCipherSpec!"
            sys.exit(1)
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
    print "	[+] Applying cipher suite:"
    print "		[+] master_secret = PRF(%s, \"master secret\" + %s + %s, 48)" % (premaster.encode('hex'), client_random.encode('hex'), server_random.encode('hex'))
    print "		[+] master_secret:", master_secret.encode('hex')

# derives keys for encryption and MAC
def derive_keys():
    global premaster, master_secret, client_random, server_random
    global client_mac_key, server_mac_key, client_enc_key, server_enc_key, rc4c, rc4s

    key_block = PRF(master_secret, "key expansion"  + server_random + client_random, 136)
    mac_size = 20
    key_size = 16

    client_mac_key = key_block[:mac_size]
    server_mac_key = key_block[mac_size:mac_size*2]
    client_enc_key = key_block[mac_size*2:mac_size*2+key_size]
    server_enc_key = key_block[mac_size*2+key_size:mac_size*2+key_size*2]
    rc4c = ARC4.new(client_enc_key)
    rc4s = ARC4.new(server_enc_key)
    print "		[+] client_mac_key:", client_mac_key.encode('hex')
    print "		[+] server_mac_key:", server_mac_key.encode('hex')
    print "		[+] client_enc_key:", client_enc_key.encode('hex')
    print "		[+] server_enc_key:", server_enc_key.encode('hex')

# HMAC SHA1 wrapper
def HMAC_sha1(key, data):
    return hmac.new(key, data, sha1).digest()

# calculates MAC and encrypts plaintext
def encrypt(plain, type, version):
    global server_mac_key, server_enc_key, server_seq, rc4s, args

    # simulate MAC failure for client
    if args.macfail:
        server_seq = 10000

    mac = HMAC_sha1(server_mac_key, nb(server_seq, 8) + type + version + nb(len(plain), 2) + plain)
    ciphertext = rc4s.encrypt(plain + mac)
    server_seq+= 1
    return ciphertext

# decrypts ciphertext and verifies MAC
def decrypt(ciphertext, type, version):
    global client_mac_key, client_enc_key, client_seq, rc4c

    d = rc4c.decrypt(ciphertext)
    mac = d[-20:]
    plain = d[:-20]

    # verify MAC
    mac_calc = HMAC_sha1(client_mac_key, nb(client_seq, 8) + type + version + nb(len(plain), 2) + plain)
    if mac!=mac_calc:
        print "[-] decrypt(): MAC verification failed!"
        sys.exit(1)
    client_seq+= 1
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


sserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sserv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sserv.bind(('127.0.0.1', args.port))
sserv.listen(0)

(s, address) = sserv.accept()
print "[+] Connection from %s:%s" % (address[0], address[1])

client_random = ""	# will hold client randomness
server_random = ""	# will hold server randomness
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

client_hello_received = False
client_change_cipher_spec_received = False
client_finished_received = False

while not client_hello_received:
    parserecord(readrecord())

s.send(server_hello())
s.send(certificate())
s.send(server_hello_done())

while not client_change_cipher_spec_received:
    parserecord(readrecord())

derive_master_secret()
derive_keys()

while not client_finished_received:
    parserecord(readrecord())

s.send(change_cipher_spec())
s.send(finished())

parserecord(readrecord())
s.send(application_data("HTTP/1.0 200 OK\r\n\r\nHello!"))

print "[+] Closing TCP connection!"
s.close()
