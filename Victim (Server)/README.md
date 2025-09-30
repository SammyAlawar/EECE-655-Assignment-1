# README

## Project summary

**Victim (Server)**
**Author:** Omar Hijazy

This repository provides tools and examples to implement and test IPv4 fragmentation behaviours in an isolated VM lab. It focuses on producing reproducible on-wire traces (PCAPs) for normal and overlapping fragments, detecting byte-level fragment overlaps/conflicts.

---

## Goals

* Produce reproducible PCAP traces for:

  * normal IPv4 fragmentation
  * overlapping fragments (malicious)
* Detect and log fragment overlaps and byte-level conflicts

---

## Repository contents (short)

* `udp_echo.py` — simple UDP echo server / listener used on the victim VM. Start this to verify whether reassembled UDP datagrams reach the application.
* `udp_echo` — (executable / helper; same purpose as `udp_echo.py`)
* `detect_overlap_verbose.py` — verbose fragment detector (uses Scapy).

  * Prints one line per fragment (start/end/frag_off/MF/etc.)
  * Stores fragments by flow and prints `>>> OVERLAP CONFLICT <<<` when two fragments overlap and overlapping bytes differ.

---

## Requirements

On each VM (attacker / victim) you will need:

* Python 3.10+ (or Python 3.x)
* `scapy` (detector & attacker scripts use Scapy)
* `sudo` / root privileges

### Install (Debian/Ubuntu)

```bash
sudo apt update
sudo pip3 install scapy
```

---

## How to run

### 1) Start the victim UDP echo listener

Run on the victim VM:

```bash
sudo python3 udp_echo.py --host 0.0.0.0 --port 9999
```

**Expected output when it receives data**

```
[*] UDP echo listening on 0.0.0.0:9999 (press Ctrl+C to stop)
RECV: b'HELLO' from ('192.168.10.20', 4444)
```

This shows that the kernel reassembled the fragments and delivered the UDP datagram to the application.

---

### 2) Start the verbose fragment detector

Run on the victim VM:

```bash
sudo python3 detect_overlap_verbose.py --iface enp0s3 --port 9999
```

Default behavior: listens on `enp0s3` for UDP to port `9999` **OR** for fragmented IP traffic.

**Typical detector fragment line**

```
[FRAG] 192.168.10.20->192.168.10.10 id=43601 proto=17 frag_off=0 start=0 end=1472 MF=1 len=1472
```

Fields explained:

* `src->dst` — packet source and destination
* `id=...` — IP identification
* `proto=...` — IP protocol (e.g., 17 for UDP)
* `frag_off=...` — fragment offset field
* `start=<byte>` `end=<byte>` — byte range within the original datagram
* `MF=<0|1>` — More Fragments flag
* `len=<rawlen>` — raw fragment length

---

## Detector outputs & interpretation

* **One line per fragment** — you will see each fragment as it arrives.
* **`>>> OVERLAP CONFLICT <<<`** — definite sign an attacker produced overlapping fragments whose overlapping bytes differ (byte-level conflict).
* **If `udp_echo` receives nothing**, likely reasons:

  * fragments had a gap (off-by-8) or ordering issue → kernel rejects reassembly
  * UDP checksum mismatch after reassembly → kernel drops packet
  * final fragment missing or malformed (first fragment must contain UDP header)

---

## Example flows to test

1. **Normal fragmentation**: attacker sends properly fragmented packets that reassemble correctly — `udp_echo` should show the payload.
2. **Overlapping fragments (malicious)**: attacker sends overlapping fragments with differing bytes in overlap — the detector should print `>>> OVERLAP CONFLICT <<<`.

