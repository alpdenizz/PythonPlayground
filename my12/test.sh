#!/bin/bash

echo "=====> Testing https://www.ut.ee/"
python tls_client.py https://www.ut.ee/
read

python tls_client.py https://127.0.0.1:4433/
read

echo "=====> Testing MAC fail"
python tls_client.py https://127.0.0.1:4434/
read

echo "=====> Testing verify fail"
python tls_client.py https://127.0.0.1:4435/
read

echo "=====> Testing https://www.swedbank.ee/ (AES bonus)"
python tls_client.py https://www.swedbank.ee/
read
