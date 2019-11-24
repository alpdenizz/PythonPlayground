#!/bin/bash

echo '$ echo -n "hello world" > plain'
echo -n "hello world" > plain
echo '$ ./aes.py -encrypt plain plain.enc'
./aes.py -encrypt plain plain.enc
rm -f plain.new
echo '$ ./aes.py -decrypt plain.enc plain.new'
./aes.py -decrypt plain.enc plain.new
echo '$ hexdump -C plain.new'
hexdump -C plain.new
echo

echo '$ echo -e -n "hello world \x01\x01\x02\x02" > plain'
echo -e -n "hello world \x01\x01\x02\x02" > plain
echo '$ ./aes.py -encrypt plain plain.enc'
./aes.py -encrypt plain plain.enc
rm -f plain.new
echo '$ ./aes.py -decrypt plain.enc plain.new'
./aes.py -decrypt plain.enc plain.new
echo '$ hexdump -C plain.new'
hexdump -C plain.new
echo

echo '$ ./aes.py -decrypt plain.enc plain.new [enter wrong pass]'
./aes.py -decrypt plain.enc plain.new

echo
rm -f big
echo '$ ./aes.py -decrypt big.enc big [password: bigfilepassword]'
./aes.py -decrypt big.enc big
echo '$ openssl dgst -sha1 big [34edb7d89a791969d710283c7464a80fe2e39249]'
openssl dgst -sha1 big
