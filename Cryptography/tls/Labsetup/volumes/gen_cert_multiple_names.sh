#!/bin/bash

# Generate Certficate signing request
openssl req -newkey rsa:2048 -config ./server_openssl.cnf -batch \
            -sha256 -keyout mycert_multiple.key -out mycert_multiple.csr

# Generate certificate for multiple domains
openssl ca -md sha256 -days 3650 -config ./CA_openssl.cnf -batch \
            -in mycert_multiple.csr -out mycert_multiple.crt \
            -cert ca.crt -keyfile ca.key