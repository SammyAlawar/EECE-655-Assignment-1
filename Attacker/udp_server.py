# udp_server.py
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 9999))    # choose a port you will send to
print("listening UDP on port 9999")
while True:
    data, addr = s.recvfrom(4096)
    print("got", len(data), "bytes from", addr, data)