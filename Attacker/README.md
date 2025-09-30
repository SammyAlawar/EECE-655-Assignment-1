# IPV4 Fragment Overlap 


This script builds and emits IPv4/UDP packets and can:

send whole UDP/IP datagrams,

split a UDP datagram into proper (non-overlapping) IPv4 fragments, or

craft overlapping fragments (final-fragment overlap or continuous multiple overlaps).


# Requirements:

Python 3

Scapy (pip3 install scapy)

sudo / root privileges required to send raw packets

UDP server running on victim machine

Optional: Wireshark/tcpdump for inspection

Quick usage
# Send non-fragmented UDP datagrams

sudo ./ip_fragment_overlap_attack.py --dst [Victim IP] --payload "Testing raw UDP/IP Datagram" --count 3

# Send proper fragments (non-overlapping)

sudo ./ip_fragment_overlap_attack.py --dst [Victim IP] --count 1 --payload "$(python3 -c 'print("B"*2000)')" --fragment --fragsize 1000 --id 50000

# Final-fragment overlap (last fragment overlaps previous)

sudo ./ip_fragment_overlap_attack.py --dst [Victim IP] --count 1 --payload "$(python3 -c 'print("A"*3000)')" --finaloverlap --fragsize 640 --id 43601

# Multiple overlapping fragments (each fragment overlaps previous)

sudo ./ip_fragment_overlap_attack.py --dst [Victim IP] --count 1 --payload "$(python3 -c 'print("A"*3000)')" --multipleoverlap --fragsize 640 --id 43601

# Write fragments to a PCAP instead of sending on-wire
sudo ./ip_fragment_overlap_attack.py --dst 192.168.19.174 --multipleoverlap -f --fragsize 32 --count 1 --pcap-out fragments.pcap


# Important flags (high-level)

--dst (required): target IP

--fragment / -f: enable fragmentation (proper fragmentation)

--finaloverlap: make the final fragment start earlier (overlap previous)

--multipleoverlap: generate a sequence of overlapping fragments

--fragsize: fragment payload size in bytes (must be multiple of 8)

--id: specify IP ID (optional)

--pcap-out <file>: write generated packets/fragments to a PCAP (no on-wire sends)

--count: number of datagrams to send

--payload: data string to carry in UDP payload

--help / -h: Show help message

Run a simple UDP receiver on the target VM:

# udp_server.py

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 9999))    # choose a port you will send to
print("listening UDP on port 9999")
while True:
    data, addr = s.recvfrom(4096)
    print("got", len(data), "bytes from", addr, data)

Capture traffic with tcpdump -w fragments.pcap or open live in Wireshark.

Use --pcap-out to create PCAPs for offline grading.


# Output 

On success you’ll either:

see the UDP server print the received payload (proper fragmentation), or

see no delivery or malformed payload when overlapping mode is selected, and Wireshark will mark "Fragment overlap"/show conflicting bytes.

PCAP files created with --pcap-out are reproducible artifacts for grading.