#!/bin/bash
echo "[+] Generating RSA key pair..."
openssl genrsa -out priv.pem 1017
openssl rsa -in priv.pem -pubout -out pub.pem

echo "[+] Testing encryption..."
echo "hello" > plain.txt
./rsa.py encrypt pub.pem plain.txt enc.txt
openssl rsautl -decrypt -inkey priv.pem -in enc.txt -out dec.txt
diff -u plain.txt dec.txt

echo "[+] Testing decryption (PEM)..."
openssl rsautl -encrypt -pubin -inkey pub.pem -in plain.txt -out enc.txt
./rsa.py decrypt priv.pem enc.txt dec.txt
diff -u plain.txt dec.txt

echo "[+] Testing decryption (DER)..."
openssl rsa -in priv.pem -outform der -out priv.key
./rsa.py decrypt priv.key enc.txt dec.txt
diff -u plain.txt dec.txt

echo "[+] Testing signing..."
dd if=/dev/urandom of=filetosign bs=1M count=1 > /dev/null 2>&1
./rsa.py sign priv.pem filetosign signature
openssl dgst -sha256 -verify pub.pem -signature signature filetosign

echo "[+] Testing successful verification..."
openssl dgst -sha256 -sign priv.pem -out signature filetosign
./rsa.py verify pub.pem signature filetosign

echo "[+] Testing failed verification..."
openssl dgst -md5 -sign priv.pem -out signature filetosign
./rsa.py verify pub.pem signature filetosign
