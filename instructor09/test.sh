#!/bin/bash

rm -f auth.pem
rm -f sign.pem

echo "$ ./esteid_info.py"
./esteid_info.py
echo
read

echo "$ ./esteid_getcert.py --cert auth --out auth.pem"
./esteid_getcert.py --cert auth --out auth.pem
echo
read

echo "$ openssl x509 -in auth.pem -text | grep O=ESTEID"
openssl x509 -in auth.pem -text | grep O=ESTEID
echo
read

echo "$ ./esteid_getcert.py --cert sign --out sign.pem"
./esteid_getcert.py --cert sign --out sign.pem
echo
read

echo "$ openssl x509 -in sign.pem -text | grep O=ESTEID"
openssl x509 -in sign.pem -text | grep O=ESTEID
echo
read

# wget https://sk.ee/upload/files/ESTEID-SK_2011.pem.crt
# wget https://sk.ee/upload/files/ESTEID-SK_2015.pem.crt

echo "$ openssl verify -CAfile ESTEID-SK_2011.pem.crt sign.pem"
openssl verify -CAfile ESTEID-SK_2011.pem.crt sign.pem
echo
read

echo "$ openssl verify -CAfile ESTEID-SK_2015.pem.crt sign.pem"
openssl verify -CAfile ESTEID-SK_2015.pem.crt sign.pem
echo
read
