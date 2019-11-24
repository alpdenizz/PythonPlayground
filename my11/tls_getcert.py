#!/usr/bin/env python

import argparse, datetime, os, socket, sys, time, urlparse # do not use any other imports/libraries

# took 3.5 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

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

# returns TLS record that contains client_hello handshake message
def client_hello():

    print "--> client_hello()"

    # list of cipher suites the client supports
    csuite = "\x00\x05"	# TLS_RSA_WITH_RC4_128_SHA
    csuite+= "\x00\x2f" # TLS_RSA_WITH_AES_128_CBC_SHA
    csuite+= "\x00\x35" # TLS_RSA_WITH_AES_256_CBC_SHA

    # add handshake message header
    t = "\x01"
    b = "\x03\x03" + nb(int(time.time()),4) + os.urandom(28) + "\x00\x00" + "\x06" + csuite + "\x01\x00" 
    l = nb(len(b),3)
    message = t + l + b

    # add record layer header
    record = "\x16\x03\x03" + nb(len(message),2) + message

    return record

# returns TLS record that contains 'Certificate unknown' fatal alert message
def alert():
    print "--> alert()"

    # add alert message
    message = "\x02" + nb(46,1)

    # add record layer header
    record = "\x15\x03\x03" + nb(len(message),2) + message

    return record

# parse TLS handshake messages
def parsehandshake(r):
    global server_hello_done_received

    # read handshake message type and length from message header
    htype = r[0]
    length = bn(r[1:4])

    if htype == "\x02":
        #content = r[4:(4+length)]
        print "	<--- server_hello()"
        server_random = r[6:38]
        timestamp = server_random[0:4]
        gmt = datetime.datetime.fromtimestamp(bn(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        sessionLength = bn(r[38:39])
        sessionEnd = 39+sessionLength
        sessid = r[39:sessionEnd]

        print "	[+] server randomness:", server_random.encode('hex').upper()
        print "	[+] server timestamp:", gmt
        print "	[+] TLS session ID:", sessid.encode('hex').upper()

        cipher = r[sessionEnd:(sessionEnd+2)]

        if cipher=="\x00\x2f":
            print "	[+] Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA"
        elif cipher=="\x00\x35":
            print "	[+] Cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA"
        elif cipher=="\x00\x05":
            print "	[+] Cipher suite: TLS_RSA_WITH_RC4_128_SHA"
        else:
            print "[-] Unsupported cipher suite selected:", cipher.encode('hex')
            sys.exit(1)
        
        compression = r[(sessionEnd+2):(sessionEnd+3)]

        if compression!="\x00":
            print "[-] Wrong compression:", compression.encode('hex')
            sys.exit(1)

    elif htype == "\x0b":
        print "	<--- certificate()"
        certlen = bn(r[7:10])
        cert = r[10:(10+certlen)]
        pem = "-----BEGIN CERTIFICATE-----\n" + cert.encode('base64') + "-----END CERTIFICATE-----\n"

        print "	[+] Server certificate length:", certlen
        if args.certificate:
            open(args.certificate,'w').write(pem)
            print "	[+] Server certificate saved in:", args.certificate
    elif htype == "\x0e":
        print "	<--- server_hello_done()"
        server_hello_done_received = True
    else:
        print "[-] Unknown Handshake Type:", htype.encode('hex')
        sys.exit(1)

    # handle the case of several handshake messages in one record
    leftover = r[(length+4):]
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):

    # read from the TLS record header the content type and length
    contentType = r[0]
    length = bn(r[3:5])
    if contentType == "\x16":
        print("<--- handshake()")
    elif contentType == "\x14":
        print("<--- change_cipher_spec()")
    elif contentType == "\x15":
        print("<--- alert()")
    elif contentType == "\x17":
        print("<--- application_data()")
    
    message = r[5:(5+length)] 
    parsehandshake(message)


# read from the socket full TLS record
def readrecord():
    global s

    record = ""

    # read the TLS record header (5 bytes)
    for _ in range(5):
        record += s.recv(1)

    # find data length
    length = bn(record[3:5])

    # read the TLS record body
    for _ in range(length):
        record += s.recv(1)

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

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
while not server_hello_done_received:
    parserecord(readrecord())
s.send(alert())

print "[+] Closing TCP connection!"
s.close()
