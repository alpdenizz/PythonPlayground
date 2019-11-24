#!/bin/bash

# must be executed before:
#openssl genrsa -out priv_subject.pem 1024
#openssl req -new -key priv_subject.pem -out req.csr

rm -f rootCA.pem
rm -f priv.pem
rm -f issued.pem

echo '$ openssl genrsa -out priv.pem 1017'
openssl genrsa -out priv.pem 1017
echo

echo '$ ./selfsigned.py priv.pem rootCA.pem'
./selfsigned.py priv.pem rootCA.pem
echo
read

echo '$ openssl verify -check_ss_sig -CAfile rootCA.pem rootCA.pem'
openssl verify -check_ss_sig -CAfile rootCA.pem rootCA.pem
echo
read
echo '$ openssl x509 -in rootCA.pem -text'
openssl x509 -in rootCA.pem -text

echo
read
echo '$ ./signcert.py priv.pem rootCA.pem req.csr issued.pem'
./signcert.py priv.pem rootCA.pem req.csr issued.pem
echo
read

echo '$ openssl verify -CAfile rootCA.pem -purpose sslserver issued.pem'
openssl verify -CAfile rootCA.pem -purpose sslserver issued.pem
echo
read
echo '$ openssl x509 -in issued.pem -text'
openssl x509 -in issued.pem -text
