# udp_echo.py - simple UDP echo server
#!/usr/bin/env python3
import socket
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--host', default='0.0.0.0')
parser.add_argument('--port', type=int, default=9999)
args = parser.parse_args()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((args.host, args.port))
print(f"[*] UDP echo listening on {args.host}:{args.port} (press Ctrl+C to stop)")
try:
    while True:
        data, addr = s.recvfrom(4096)
        print("RECV:", data, "from", addr)
        s.sendto(data, addr)
except KeyboardInterrupt:
    print("[!] Stopping.")
finally:
    s.close()