#!/bin/sh

# This script is used to simulate a HTTP client that connects to a HTTP server
# listening on port 8000 and then closes the connection with a RST packet.

python - << EOF
import socket
import struct
#import time

def client(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect((host, port))

    # By setting onoff to 1 and linger to 0, we are telling the kernel to
    # discard any unsent data and send an RST when the socket is closed:
    # https://notes.shichao.io/unp/ch7/#so_linger-socket-option
    l_onoff = 1
    l_linger = 0
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))

    # Uncomment the following line and kill the process
    #time.sleep(99999)

    s.close()

client('0.0.0.0', 8000)
EOF
