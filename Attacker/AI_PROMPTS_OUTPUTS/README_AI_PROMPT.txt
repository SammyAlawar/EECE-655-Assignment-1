Let ^ indicate that I used the text, and ^^ indicate that i didn't include the text wrapped.
(^ and ^^ will be inserted above and at the end of each block)

ME: what should i include in the readme of my attacker code? Please create a brief one

GPT Output:
^^
# README — IP Fragment Overlap Attacker

**Project:** IP fragmentation / overlap attacker
**Author:** Sammy Alawar
**Language:** Python 3 (Scapy)
**File:** `ip_fragment_overlap_attack.py` (aka `attacker_overlap_from_colleague.py`)

---
^^

^
## Purpose (short)

This script builds and emits IPv4/UDP packets and can:

* send whole UDP/IP datagrams,
* split a UDP datagram into **proper** (non-overlapping) IPv4 fragments, or
* craft **overlapping** fragments (final-fragment overlap or continuous multiple overlaps).

^

^^
It is intended for **controlled lab use** (testing detectors, studying reassembly behavior). Do **not** use on public networks.
^^
---

^
## Requirements

* Python 3
* Scapy (`pip3 install scapy`)
* sudo / root privileges required to send raw packets
* Optional: Wireshark/tcpdump for inspection

---

## Quick usage

```bash
# send non-fragmented UDP datagrams
sudo ./ip_fragment_overlap_attack.py --dst 192.168.19.174 --count 1 --payload "TEST"

# send proper fragments (non-overlapping)
sudo ./ip_fragment_overlap_attack.py --dst 192.168.19.174 --fragment --fragsize 48 --count 1

# final-fragment overlap (last fragment overlaps previous)
sudo ./ip_fragment_overlap_attack.py --dst 192.168.19.174 --finaloverlap -f --fragsize 48 --count 1

# multiple overlapping fragments (each fragment overlaps previous)
sudo ./ip_fragment_overlap_attack.py --dst 192.168.19.174 --multipleoverlap -f --fragsize 32 --count 1

# write fragments to a PCAP instead of sending on-wire
sudo ./ip_fragment_overlap_attack.py --dst 192.168.19.174 --multipleoverlap -f --fragsize 32 --count 1 --pcap-out fragments.pcap
```

---

## Important flags (high-level)

* `--dst` (required) — target IP
* `--fragment` / `-f` — enable fragmentation (proper fragmentation)
* `--finaloverlap` — make the final fragment start earlier (overlap previous)
* `--multipleoverlap` — generate a sequence of overlapping fragments
* `--fragsize` — fragment payload size in bytes (must be multiple of 8)
* `--id` — specify IP ID (otherwise default)
* `--pcap-out <file>` — write generated packets/fragments to a PCAP (no on-wire sends)
* `--count` — number of datagrams to send
* `--payload` — data string to carry in UDP payload

---
^

^^
## Notes & gotchas

* **Why Scapy?** Scapy provides low-level control of IP header fields (`frag`, `flags`, `id`) and PCAP export — necessary to craft overlaps that the OS socket API won't let you create.
* **Fragment offset units:** IPv4 `frag` is in 8-byte units. Non-final fragments *should* have lengths that are multiples of 8 — the script enforces `fragsize % 8 == 0`.
* **Minimum fragsize for continuous overlap:** For continuous (multiple) overlaps the script enforces a practical minimum (e.g., 16) because half-fragment overlaps must be representable using 8-byte units. Final-fragment overlap is a single adjustment and therefore is allowed with smaller fragsizes (still subject to 8-byte granularity).
* **MTU:** Make sure generated fragments fit the link MTU (IP header + fragment payload <= MTU), otherwise lower layers may re-fragment and invalidate offsets.
* **Safety:** Run only in isolated VMs or a lab network. Do not target external hosts or university networks.

^^
---

^
## Testing tips

1. Run a simple UDP receiver on the target VM:

   ```python
   # udp_server.py
   import socket
   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   s.bind(("0.0.0.0", 9999))
   print("listening UDP on port 9999")
   while True:
       data, addr = s.recvfrom(4096)
       print("got", len(data), "bytes from", addr, data)
   ```
2. Capture traffic with `tcpdump -w fragments.pcap` or open live in Wireshark.
3. Use `--pcap-out` to create PCAPs for offline grading.

---

## Output / evidence

* On success you’ll either:

  * see the UDP server print the received payload (proper fragmentation), or
  * see no delivery or malformed payload (overlap/conflict cases), and Wireshark will mark "Fragment overlap"/show conflicting bytes.
* PCAP files created with `--pcap-out` are reproducible artifacts for grading.

^
---
^^
## Ethical note

This tool is for educational/research use in **isolated test environments only**. Do not use against third-party systems or public networks.

---

## Contact / contribution

Author: **Sammy Alawar** — implemented attacker, test cases, and Wireshark analysis.
(Include teammate contributions in the report as required by the assignment.)

---

If you want, I can:

* produce a 1-page README PDF formatted for the repo, or
* append a short 1-paragraph example for the grader describing how to reproduce the three demo PCAPs (proper, final-overlap, multiple-overlap). Which would you like?
^^