#!/bin/bash

fileName="mycert"   
mySubject="/CN=www.pinto2022.com"

# Generate RSA key pair and certificate request
openssl req -newkey rsa:2048 -batch \
            -sha256 -days 3650 \
            -keyout $fileName.key -out $fileName.csr \
            -subj "$mySubject" \
            -passout pass:dees # Encrypt the private key using "dees"

# Generate a certificate for www.pinto2022.com
openssl ca -config CA_openssl.cnf -policy policy_anything \
           -md sha256 -days 3650 \
           -in $fileName.csr -out $fileName.crt -batch \
           -cert ca.crt -keyfile ca.key -passin pass:dees