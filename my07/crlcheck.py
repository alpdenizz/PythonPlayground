#!/usr/bin/env python
  
import argparse, hashlib, datetime, re, socket, sys, os, urlparse  # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder
  
# took 6.0 hours (please specify here how much time your solution required)
  
# parse arguments
parser = argparse.ArgumentParser(description='Check certificates against CRL', add_help=False)
parser.add_argument("url", type=str, help="URL of CRL (DER)")
parser.add_argument("--issuer", required=True, metavar='issuer', type=str, help="CA certificate that has issued the certificates (DER/PEM)")
parser.add_argument("--certificates", required=True, metavar='cert', type=str, nargs='+', help="Certificates to check (DER/PEM)")
args = parser.parse_args()

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

def lookup(b):
    if b == '0000':
        return '0'
    elif b == '0001':
        return '1'
    elif b == '0010':
        return '2'
    elif b == '0011':
        return '3'
    elif b == '0100':
        return '4'
    elif b == '0101':
        return '5'
    elif b == '0110':
        return '6'
    elif b == '0111':
        return '7'
    elif b == '1000':
        return '8'
    elif b == '1001':
        return '9'
    elif b == '1010':
        return 'a'
    elif b == '1011':
        return 'b'
    elif b == '1100':
        return 'c'
    elif b == '1101':
        return 'd'
    elif b == '1110':
        return 'e'
    elif b == '1111':
        return 'f'

def convert(bitstr):
    l = len(bitstr)
    mod = l % 4
    if mod != 0:
        bitstr = '0'*(4-mod)+bitstr
    hexRep = ''
    while(True):
        add = bitstr[0:4]
        if(add == ''):
            break
        else:
            hexRep = hexRep + lookup(add)
            bitstr = bitstr[4:]
    return hexRep.decode('hex')

def modify(str):
    str = str.replace("(","")
    str = str.replace(")","")
    str = str.replace(",","")
    str = str.replace(" ","")
    return str

def get_pubkey_certificate(filename):
    # reads certificate and returns (n, e) from subject public key
    cert = open(filename).read()
    cert = pem_to_der(cert)
    decoded = decoder.decode(cert)
    bitstr = modify(str(decoded[0][0][6][1]))
    content = int_to_bytestring2(bitstr_to_int(bitstr))
    #print(content.encode('hex'))
    pubkey = decoder.decode(content)[0]
    return int(pubkey[0]), int(pubkey[1])


def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    loc = plaintext.find('\x00',1)
    return plaintext[(loc+1):]

def digestinfo_der(m, alg_oid):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA-X digest of m
    digest = ""
    hash_oid = []

    if alg_oid == [1,2,840,113549,1,1,5]:
        digest = hashlib.sha1(m).digest()
        hash_oid = [1,3,14,3,2,26]
    elif alg_oid == [1,2,840,113549,1,1,11]:
        digest = hashlib.sha256(m).digest()
        hash_oid = [2,16,840,1,101,3,4,2,1]
    elif alg_oid == [1,2,840,113549,1,1,12]:
        digest = hashlib.sha384(m).digest()
        hash_oid = [2,16,840,1,101,3,4,2,2]
    elif alg_oid == [1,2,840,113549,1,1,13]:
        digest = hashlib.sha512(m).digest()
        hash_oid = [2,16,840,1,101,3,4,2,3]
    else:
        print "[-] digestinfo_der(): unrecognized alg_oid:", alg_oid
        sys.exit(1)
    
    digestinfo = asn1_sequence( \
        asn1_sequence( \
                asn1_objectidentifier(hash_oid) + \
                asn1_null()) + \
        asn1_octetstring(digest))

    return digestinfo

def verify(certfile, c, contenttoverify, alg_oid):
    # returns 1 on "Verified OK" and 0 otherwise

    n,e = get_pubkey_certificate(certfile)
    #print(n)
    #print(e)
    m = pow(c,e,n)
    bytesize_n = len(int_to_bytestring2(n))
    message = int_to_bytestring(m,bytesize_n)
    message = pkcsv15pad_remove(message)
    digestinfo_from_signature = message
    digestinfo_from_content = digestinfo_der(contenttoverify,alg_oid)

    if digestinfo_from_signature == digestinfo_from_content:
        return 1
    else:    
        return 0


# list of serial numbers to check
serials = []

# download CRL using python sockets
def download_crl(url):

    print "[+] Downloading", url

    # parsing url
    result = urlparse.urlparse(url)
    host = result.netloc
    path = result.path
   
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((host,80))
    request = "GET "+path+" HTTP/1.1" + "\r\n"+"Host: "+host+"\r\n"+"Connection: close"+"\r\n"+"\r\n"
    s.send(request)

    # get response header
    header = ''
    while(not header.endswith("\r\n\r\n")):
        header = header + s.recv(1)
    

    # get content-length value
    length = int(re.search('content-length:\s*(\d+)\s', header, re.S+re.I).group(1))

    # receive CRL (get response body)
    crl = ''
    for _ in range(length):
        crl += s.recv(1)
    return crl

# verify if the CRL is signed by the issuer and whether the CRL is fresh
def verify_crl(issuer, crl):
    crl = pem_to_der(crl)
    decoded = decoder.decode(crl)
    tbsCertList = encoder.encode(decoded[0][0])
    signatureValue = modify(str(decoded[0][2]))
    signature = bitstr_to_int(signatureValue)
    alg_oid = str(decoded[0][1][0])
    alg_oid = map(int,alg_oid.split("."))

    if verify(issuer, signature, tbsCertList, alg_oid):
        print "[+] CRL signature check successful!"
    else:
        print "[-] CRL signature verification failed!"
        sys.exit(1)

    tbsCertList = decoded[0][0]
    now = datetime.datetime.now()
    thisUpdate = datetime.datetime.strptime(str(tbsCertList[3]),'%y%m%d%H%M%SZ')
    nextUpdate = datetime.datetime.strptime(str(tbsCertList[4]),'%y%m%d%H%M%SZ')

    if now < thisUpdate or now > nextUpdate:
        print "[-] CRL outdated (nextUpdate: %s) (now: %s)" % (nextUpdate, now)
        sys.exit(1)


# verify if the certificates are signed by the issuer and add them to the list 'serials'
def load_serials(issuer, certificates):
    global serials

    for certificate in certificates:
        content = open(certificate).read()
        content = pem_to_der(content)
        decoded = decoder.decode(content)
        tbsCertificate = encoder.encode(decoded[0][0])
        signatureValue = str(decoded[0][2])
        signature = bitstr_to_int(signatureValue)
        alg_oid = str(decoded[0][1][0])
        alg_oid = map(int,alg_oid.split("."))

        if verify(issuer, signature, tbsCertificate, alg_oid):
            serial = int(decoded[0][0][1])
            print "[+] Serial %s (%s) loaded" % (serial, certificate)
            serials.append(serial)
        else:
            serial = int(decoded[0][0][1])
            print "[-] Serial %s (%s) not loaded: not issued by CA" % (serial, certificate)


# check if the certificates are revoked
# if revoked -- print revocation date and reason (if available)
def check_revoked(crl):
    global serials

    CRLReason = {
	0: 'unspecified',
	1: 'keyCompromise',
	2: 'cACompromise',
	3: 'affiliationChanged',
	4: 'superseded',
	5: 'cessationOfOperation',
	6: 'certificateHold',
	8: 'removeFromCRL',
	9: 'privilegeWithdrawn',
	10: 'aACompromise',
	}

    # loop over revokedCerts
    for revokedCert in decoder.decode(crl)[0][0][5]:
        
        serial = revokedCert[0]
        revocationDate = datetime.datetime.strptime(str(revokedCert[1]),'%y%m%d%H%M%SZ')
        extensions = revokedCert[2]
        # if revoked serial is in our interest
        if serial in serials:
            # check if the extensions are present
            if extensions != '':
                reason = ''
                for extension in extensions:
                    if(str(extension[0]) == "2.5.29.21"):
                        reason = CRLReason[decoder.decode(str(extension[1]))[0]]
                        break
                if(reason == ''):
                    reason = "No reason"
                print "[-] Certificate %s revoked: %s %s" % (serial, revocationDate, reason)


# download CRL
crl = download_crl(args.url)

# verify CRL
verify_crl(args.issuer, crl)

# load serial numbers from valid certificates
load_serials(args.issuer, args.certificates)

# check revocation status
check_revoked(crl)