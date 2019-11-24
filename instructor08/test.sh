#!/bin/bash

if [ "$1" == "server" ]; then
	./ocspresponder.py --privkey priv.pem --cacert rootCA.pem --revoked issued1.pem issued2.pem
else
        echo "Testing revoked"
	openssl ocsp -url http://127.0.0.1:8888/ -no_nonce -VAfile rootCA.pem -issuer rootCA.pem -cert issued2.pem
        echo
        read

        echo "Testing good"
	openssl ocsp -url http://127.0.0.1:8888/ -no_nonce -VAfile rootCA.pem -issuer rootCA.pem -cert issued3.pem
        echo
        read

        echo "Testing unknown"
	openssl ocsp -url http://127.0.0.1:8888/ -no_nonce -VAfile rootCA.pem -issuer rootCA2.pem -cert issued3.pem
        echo
        read

        echo "Testing nonce"
	openssl ocsp -url http://127.0.0.1:8888/ -nonce -VAfile rootCA.pem -issuer rootCA.pem -cert issued2.pem
        echo
        read

        echo "Testing GET response"
	curl --verbose http://127.0.0.1:8888/
        echo
        read

        echo "Testing unauthorized"
        # modify URL with IP address of your external network interface
	openssl ocsp -url http://192.168.1.20:8888/ -no_nonce -VAfile rootCA.pem -issuer rootCA.pem -cert issued2.pem
        echo
        read

fi
