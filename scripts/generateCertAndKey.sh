#!/bin/bash

CONFIG_FILE=openssl.cfg
CERT_FILENAME=cert.pem
KEY_FILENAME=key.pem

COUNTRY="NA"
EMAIL="none"
LOCATION="none"
COMMON_NAME="none"
ORGANIZATION="none"
STATE="none"
ORG_UNIT="none"

while getopts ":c:e:l:n:o:s:u:" opt; do
    case $opt in
        c) COUNTRY="$OPTARG";;
        e) EMAIL="$OPTARG";;
        l) LOCATION="$OPTARG";;
        n) COMMON_NAME="$OPTARG";;
        o) ORGANIZATION="$OPTARG";;
        s) STATE="$OPTARG";;
        u) ORG_UNIT="$OPTARG";;
    esac
done


# Create the configuration file needed for OpenSSL to create the cert and key
cat > $CONFIG_FILE <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $LOCATION
O = $ORGANIZATION
OU = $ORG_UNIT
CN = $COMMON_NAME
emailAddress = $EMAIL

[ v3_req ]

EOF

# generate private key
openssl genrsa -out $KEY_FILENAME 1024

# generate self signed cert
openssl req -new -x509 -out $CERT_FILENAME -key $KEY_FILENAME -days 3650 -extensions v3_req -config $CONFIG_FILE

rm $CONFIG_FILE
