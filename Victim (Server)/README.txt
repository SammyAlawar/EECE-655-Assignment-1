# README

## Project summary

**Victim (Server)**
**Author:** Omar Hijazy

This repository provides tools and examples to implement and test IPv4 fragmentation behaviours in an isolated VM lab. It focuses on producing reproducible on-wire traces (PCAPs) for normal and overlapping fragments, detecting byte-level fragment overlaps/conflicts, and optionally mitigating attackers with simple `iptables` rules.

---

## Goals

* Produce reproducible PCAP traces for:

  * normal IPv4 fragmentation
  * overlapping fragments (malicious)
* Detect and log fragment overlaps and byte-level conflicts
* Optionally mitigate attackers by inserting `iptables` DROP rules

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
* `tcpdump` (for capturing PCAPs)
* `sudo` / root privileges for raw packet sending and `iptables` commands

### Install (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y python3-pip tcpdump iptables
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

Run on the victim VM (or a sniffing VM that sees the attacker packets):

```bash
sudo python3 detect_overlap_verbose.py --iface enp0s3 --port 9999
```

Default behavior: listens on `enp0s3` for UDP to port `9999` **OR** for fragmented IP traffic (uses a BPF filter).

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

## Troubleshooting tips

* Make sure the sniffing interface sees the attacker packets (if running detector on a separate VM).
* Use `tcpdump` to capture packets for manual inspection:

  ```bash
  sudo tcpdump -i enp0s3 -w capture.pcap 'udp port 9999 or ip[6:2] & 0x1fff != 0'
  ```

  (BPF example: capture UDP 9999 or any fragmented IP)
* If `udp_echo` doesn't print received packets but the detector sees fragments, examine:

  * fragment offsets and whether they are aligned to 8-byte boundaries
  * UDP checksum (reassembly can produce wrong checksum if fragments manipulated)
  * whether first fragment contains the UDP header

---

## Optional mitigation (example)

You can block an attacker IP with `iptables`. Replace `<ATTACKER_IP>` and adapt interface as needed:

```bash
# Drop all traffic from attacker
sudo iptables -I INPUT -s <ATTACKER_IP> -j DROP

# Or drop only fragmented packets from attacker
sudo iptables -I INPUT -s <ATTACKER_IP> -m frag -j DROP
```

Notes:

* `-I INPUT` inserts rule at top (highest priority).
* Use cautiously; `iptables` rules affect system networking and may block legitimate traffic.
* Persist rules if desired (e.g., using `iptables-save`/`iptables-restore` or system-specific persistence).

---

## Capture PCAPs for reproducible traces

Use `tcpdump` on the sniffing/victim interface to capture traces for later analysis:

```bash
sudo tcpdump -i enp0s3 -s 0 -w normal_fragments.pcap 'udp port 9999'
sudo tcpdump -i enp0s3 -s 0 -w overlapping_fragments.pcap 'udp port 9999 or ip[6:2] & 0x1fff != 0'
```

Open the PCAPs with Wireshark or `tshark` to inspect fragment offsets, payload bytes, and overlaps.

---

## Example flows to test

1. **Normal fragmentation**: attacker sends properly fragmented packets that reassemble correctly — `udp_echo` should show the payload.
2. **Overlapping fragments (malicious)**: attacker sends overlapping fragments with differing bytes in overlap — the detector should print `>>> OVERLAP CONFLICT <<<`. Kernel behavior may vary (which fragment wins depends on kernel/version and reassembly strategy).

---

## Author & contact

**Author:** Omar Hijazy

---

## License

(Include a license here if you want — e.g., MIT. If you want, tell me which license and I’ll add the standard text.)

---

If you want, I can:

* add a short `Usage` section with example attacker scripts and exact CLI flags,
* include a ready-to-copy `iptables` mitigation script,
* or produce a `CONTRIBUTING.md` and a short MIT license block. Which would you like next?
