#!/bin/bash

# Generating self-signed certificate for the CA
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
            -keyout ca.key -out ca.crt