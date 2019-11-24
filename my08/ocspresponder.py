#!/usr/bin/env python

import argparse, datetime, hashlib, re, socket, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder

# took 10.5 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='OCSP responder', add_help=False)
parser.add_argument("--privkey", required=True, metavar='privkey', type=str, help="CA private key (DER/PEM)")
parser.add_argument("--cacert", required=True, metavar='cacert', type=str, help="CA certificate (DER/PEM)")
parser.add_argument("--revoked", required=True, metavar='cert', type=str, nargs='+', help="Revoked certificates (DER/PEM)")
args = parser.parse_args()

def lookup(h):
    if h == '0':
        return '0000'
    elif h == '1':
        return '0001'
    elif h == '2':
        return '0010'
    elif h == '3':
        return '0011'
    elif h == '4':
        return '0100'
    elif h == '5':
        return '0101'
    elif h == '6':
        return '0110'
    elif h == '7':
        return '0111'
    elif h == '8':
        return '1000'
    elif h == '9':
        return '1001'
    elif h == 'a' or h == 'A':
        return '1010'
    elif h == 'b' or h == 'B':
        return '1011'
    elif h == 'c' or h == 'C':
        return '1100'
    elif h == 'd' or h == 'D':
        return '1101'
    elif h == 'e' or h == 'E':
        return '1110'
    elif h == 'f' or h == 'F':
        return '1111'

def modify(str):
    str = str.replace("(","")
    str = str.replace(")","")
    str = str.replace(",","")
    str = str.replace(" ","")
    return str

def int_to_bytestring(i, length):
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

def asn1_len(content_str):
    length_bytes = int_to_bytestring2(len(content_str)) or "\x00"

    if len(content_str) < 128:
        return length_bytes

    return chr(0b10000000 | len(length_bytes)) + length_bytes

def asn1_integer(i):
    s = int_to_bytestring2(i) or "\x00"

    # checking if the most significant bit of the most significant (left-most) byte is 1
    if ord(s[0]) & 0b10000000 == 0b10000000:
        s = "\x00" + s

    return chr(0b00000010) + asn1_len(s) + s

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

def asn1_generalizedtime(time):
    # time - bytestring containing timestamp in UTCTime format (e.g., "121229010100Z")
    # returns DER encoding of UTCTime
    return chr(0x18)+asn1_len(time)+time

def asn1_sequence(der):
    # der - DER bytestring to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return chr(0x30)+asn1_len(der)+der

def asn1_tagimplicit(der,tag):
    #either null or sequence (other cases not considered)
    if der is "":
        return chr(0b10000000 | tag) + asn1_len(der) + der
    else:
        return chr(0b10100000 | tag) + asn1_len(der) + der

def asn1_enumerated(i):
    s = int_to_bytestring2(i) or "\x00"

    # checking if the most significant bit of the most significant (left-most) byte is 1
    if ord(s[0]) & 0b10000000 == 0b10000000:
        s = "\x00" + s

    return chr(0b00001010) + asn1_len(s) + s

def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type
    t = 0b10100000 | tag
    return chr(t)+asn1_len(der)+der

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
    s = chr(pad_len) + int_to_bytestring(i, length_in_bytes)
    return chr(0b00000011) + asn1_len(s) + s

def asn1_bitstring2(bytestr):
    encoded = bytestr.encode('hex')
    bitstr = ''
    for c in encoded:
        bitstr = bitstr + lookup(c)
    return asn1_bitstring(bitstr)

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

def get_pubkey_cert(cert):
    # reads certificate and returns subjectPublicKey
    certificate = open(cert).read()
    certificate = pem_to_der(certificate)
    subjectPublicKey = modify(str(decoder.decode(certificate)[0][0][6][1]))
    return int_to_bytestring2(bitstr_to_int(subjectPublicKey))

def get_privkey(filename):
    # reads private key file and returns (n, d)
    content = open(filename).read()
    content = pem_to_der(content)
    privkey = decoder.decode(content)
    return int(privkey[0][1]), int(privkey[0][3])

def hashString(m):
    digest = ""
    digest = hashlib.sha1(m).digest()
    return digest

def digestinfo_der(m):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA1 digest of file
    digest = hashString(m)
    hash_oid = [1,3,14,3,2,26]
    digestinfo = asn1_sequence( \
        asn1_sequence( \
                asn1_objectidentifier(hash_oid) + \
                asn1_null()) + \
        asn1_octetstring(digest))

    return digestinfo

def sign(m, keyfile):
    plaintext = digestinfo_der(m)
    n,d = get_privkey(keyfile)
    padded_text = pkcsv15pad_sign(plaintext,n)
    m = bytestring_to_int(padded_text)
    s = pow(m,d,n)
    bytesize_n = len(int_to_bytestring2(n))
    return int_to_bytestring(s,bytesize_n)

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5

    # calculate byte size of modulus n
    bytesize_n = len(int_to_bytestring2(n))
    
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

# serial numbers of revoked certificates
serials = []

# in a loop obtain DER encoded OCSP request and send response
def process_requests():

    sserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sserv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sserv.bind(('', 8888))
    sserv.listen(0)

    stop = False
    while True:
        (s, address) = sserv.accept()
        print "[+] Connection from %s:%s" % (address[0], address[1])

        if(str(address[0]) != '127.0.0.1'):
            answer = asn1_sequence(asn1_enumerated(6))
            # prepend HTTP response header
            responseHeader = "HTTP/1.0 200 OK"+"\r\n"+ \
            "content-type: application/ocsp-response"+"\r\n"+ \
            "content-transfer-encoding: binary"+ \
            "content-length: "+str(len(answer))+"\r\n"+ \
            "\r\n"

            s.send(responseHeader)
            # send the response
            s.send(answer)
            s.close()
        else:
            # read HTTP request header
            header = ''
            current = ''
            answer = ''
            while(not stop):
                current = s.recv(1)
                header = header + current
                if(header.endswith("\r\n\r\n")):
                    stop = True
                    break

            # send error message if GET request (bonus)
            if(stop):
                if(header[0:3]=="GET"):
                    stop = False
                    answer = "<html><body>This server is processing only OCSP <u><b>POST</b></u> requests!</body></html>"
                    # prepend HTTP response header
                    responseHeader = "HTTP/1.0 200 OK"+"\r\n"+ \
                    "content-type: text/html"+"\r\n"+ \
                    "content-length: "+str(len(answer))+"\r\n"+ \
                    "\r\n"

                    s.send(responseHeader)
                    # send the response
                    s.send(answer)
                    s.close()
        
                else:
                    # read OCSP request
                    length = int(re.search('content-length:\s*(\d+)\s', header, re.S+re.I).group(1))
                    ocspRequest = ''
                    for _ in range(length):
                        ocspRequest += s.recv(1)
                    stop = False
                    # produce OCSP response
                    answer = produce_response(ocspRequest,str(address[0]))

                    # prepend HTTP response header
                    responseHeader = "HTTP/1.0 200 OK"+"\r\n"+ \
                    "content-type: application/ocsp-response"+"\r\n"+ \
                    "content-transfer-encoding: binary"+ \
                    "content-length: "+str(len(answer))+"\r\n"+ \
                    "\r\n"

                    s.send(responseHeader)
                    # send the response
                    s.send(answer)
                    s.close()

# load serials of revoked certificates to list 'serials'
def load_serials(certificates):
    global serials

    for certificate in certificates:
        content = open(certificate).read()
        content = pem_to_der(content)
        decoded = decoder.decode(content)
        serial = int(decoded[0][0][1])
        print "[+] Serial %s (%s) loaded" % (serial, certificate)
        serials.append(serial)

# produce OCSP response for DER encoded request
def produce_response(req, ip):
    global args, serials
    # return unauthorized(6) if non-localhost client (bonus)
    if(ip != '127.0.0.1'):
        finalDER = asn1_sequence(asn1_enumerated(6))
        return finalDER
    else:

        # get subject name from CA certificate
        ca = open(args.cacert).read()
        ca = pem_to_der(ca)
        subject_name = encoder.encode(decoder.decode(ca)[0][0][5])

        # get subjectPublicKey (not subjectPublicKeyInfo) from CA certificate
        subjectPublicKey = get_pubkey_cert(args.cacert)
        certID = decoder.decode(req)[0][0][0][0][0]
        # get serial number from request
        serial = int(certID[3])

        reqNameHash = str(certID[1])
        reqKeyHash = str(certID[2])
    
        # calculate SHA1 hash of CA subject name and CA public key (return CertStatus 'unknown' if not issued by CA)
        issuerNameHash = hashString(subject_name)
        issuerKeyHash = hashString(subjectPublicKey)
        CertStatus = ''
        if(reqNameHash != issuerNameHash or reqKeyHash != issuerKeyHash):
            print("This is not issued by CA!")
            CertStatus = asn1_tagimplicit("", 2)
    
        else:
            # return 'revoked' CertStatus if serial in serials (otherwise return 'good')
            if(serial in serials):
                CertStatus = asn1_tagimplicit(
                    (asn1_generalizedtime("20110101111111Z") +
                    asn1_tag_explicit(asn1_enumerated(2),0))
                ,1)
            else:
                CertStatus = asn1_tagimplicit("",0)

        requestExtension = ''
        #nonce extension (bonus)
        if(len(decoder.decode(req)[0][0]) == 1):
            requestExtension = ''
        else:
            oid = [1,3,6,1,5,5,7,48,1,2]
            value = decoder.decode(req)[0][0][1][0][1]
            requestExtension = asn1_sequence(
                asn1_sequence(
                    asn1_objectidentifier(oid) +
                    asn1_octetstring(str(value))
                )
            )
            requestExtension = asn1_tag_explicit(requestExtension,1)
            

        timestr = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%SZ")
        tbsResponseData = asn1_sequence( 
            asn1_tagimplicit(subject_name,1) + 
            asn1_generalizedtime(timestr) + 
            asn1_sequence( 
                asn1_sequence( 
                    encoder.encode(certID) + 
                    CertStatus + 
                    asn1_generalizedtime(timestr)
                    )
                ) +
            requestExtension
            )
        # get signature of tbsResponseData
        signature = sign(tbsResponseData, args.privkey)

        resp = asn1_sequence(
            tbsResponseData +
            asn1_sequence(
                    asn1_objectidentifier([1,2,840,113549,1,1,5]) +
                    asn1_null()
                ) +
            asn1_bitstring2(signature)
        )

        # return DER encoded OCSP response
        finalDER = asn1_sequence(
            asn1_enumerated(0) +
            asn1_tag_explicit(
                asn1_sequence(
                    asn1_objectidentifier([1,3,6,1,5,5,7,48,1,1]) +
                    asn1_octetstring(resp)
            ),0)
        )
        return finalDER

load_serials(args.revoked)
process_requests()
