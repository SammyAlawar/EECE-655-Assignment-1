README
Project summary
Victim (Server)
Author: Omar Hijazy

====================================================================================================

We implement and test IPv4 fragmentation behaviours (normal fragmentation vs overlapping fragments) in an isolated VM lab.
Goals:

produce reproducible on-wire traces (PCAP) for normal and overlapping fragments,

detect and log fragment overlaps and byte-level conflicts,

optionally mitigate attackers by inserting iptables DROP rules.

This repo contains:

a UDP echo victim used to check whether reassembled UDP datagrams are delivered to apps, and

a verbose fragment detector that prints every fragment seen and reports byte-level conflicts (overlaps with differing bytes).

Files (short)

udp_echo.py — simple UDP echo server / listener used on the victim VM. Run it to show whether reassembled UDP datagrams reach the application. 

udp_echo

detect_overlap_verbose.py — verbose detector using Scapy: prints per-fragment lines (start/end/frag_off/MF), stores fragments per flow, and prints >>> OVERLAP CONFLICT <<< when two fragments overlap and the overlapping bytes differ.

====================================================================================================

Requirements:

On each VM (attacker / victim) you will need:

=> Python 3.10+ (or 3.x)

=> scapy (sudo pip3 install scapy) — detector & attacker scripts use Scapy

=> tcpdump (for capturing PCAPs)

=> sudo/root for packet sending and iptables commands

to install:
sudo apt update
sudo apt install -y python3-pip tcpdump iptables
sudo pip3 install scapy

====================================================================================================

How to run:
1) Start the victim listener (UDP echo):
=> On the victim VM:

# start UDP echo (prints received messages)
sudo python3 udp_echo.py --host 0.0.0.0 --port 9999


=> Output when it receives data:

[*] UDP echo listening on 0.0.0.0:9999 (press Ctrl+C to stop)
RECV: b'HELLO' from ('192.168.10.20', 4444)

2) Start the verbose detector
=> On the victim VM (or a sniffing VM that sees attacker packets):

# default listens on enp0s3 port 9999 (BPF filter: UDP to port 9999 OR fragmented IP)
sudo python3 detect_overlap_verbose.py --iface enp0s3 --port 9999

=> Typical detector fragment line:

[FRAG] 192.168.10.20->192.168.10.10 id=43601 proto=17 frag_off=0 start=0 end=1472 MF=1 len=1472

====================================================================================================

Expected outputs & how to read them:

* Detector lines: one per fragment. Fields: src->dst id=... proto=... frag_off=<ip.frag> start=<byte> end=<byte> MF=<0|1> len=<rawlen>.

* >>> OVERLAP CONFLICT <<<: a definite sign attacker produced overlapping fragments that differ at the same byte positions (conflict).

* udp_echo receives nothing: likely causes:

	* fragments had a gap (off-by-8) or ordering issue → kernel rejects reassembly,

	* UDP checksum mismatch after reassembly → kernel drops packet,

	* final fragment missing or malformed (first fragment must contain UDP header).
