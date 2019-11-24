#!/bin/bash

#wget https://sk.ee/upload/files/EE_Certification_Centre_Root_CA.pem.crt -O EECCRCA.pem

echo '$ ./crlcheck.py https://sk.ee/crls/eeccrca/eeccrca.crl --issuer EECCRCA.pem --certificates revoked.pem valid.pem nonissued.pem'
./crlcheck.py https://sk.ee/crls/eeccrca/eeccrca.crl --issuer EECCRCA.pem --certificates revoked.pem valid.pem nonissued.pem
echo
read

echo '$ ./crlcheck.py http://kodu.ut.ee/~arnis/appcrypto2018/outdated.crl --issuer EECCRCA.pem --certificates revoked.pem valid.pem nonissued.pem'
./crlcheck.py http://kodu.ut.ee/~arnis/appcrypto2017/outdated.crl --issuer EECCRCA.pem --certificates revoked.pem valid.pem nonissued.pem
echo
read

echo '$ ./crlcheck.py http://kodu.ut.ee/~arnis/appcrypto2018/badsign.crl --issuer EECCRCA.pem --certificates revoked.pem valid.pem nonissued.pem'
./crlcheck.py http://kodu.ut.ee/~arnis/appcrypto2017/badsign.crl --issuer EECCRCA.pem --certificates revoked.pem valid.pem nonissued.pem
echo
read

