#!/bin/bash

echo "=====> Testing https://www.ut.ee/"
./tls_client.py https://www.ut.ee/
read

gnome-terminal --tab -e "python tls_server.py --port 4433"
./tls_client.py https://127.0.0.1:4433/
read

echo "=====> Testing MAC fail"
gnome-terminal --tab -e "python tls_server.py --port 4434 --macfail"
./tls_client.py https://127.0.0.1:4434/
read

echo "=====> Testing verify fail"
gnome-terminal --tab -e "python tls_server.py --port 4435 --verifyfail"
./tls_client.py https://127.0.0.1:4435/
read

echo "=====> Testing https://www.swedbank.ee/ (AES bonus)"
./tls_client.py https://www.swedbank.ee/
read
