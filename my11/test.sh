#!/bin/bash

rm -f server.pem

echo "Testing eesti.ee:"
./tls_getcert.py https://www.eesti.ee/ --certificate server.pem	
read
openssl x509 -in server.pem -text | grep 'Subject:'
read

echo "Testing ut.ee:"
./tls_getcert.py https://www.ut.ee/
echo
read

echo "Testing danskebank.ee:"
./tls_getcert.py https://danskebank.ee/
echo
read


