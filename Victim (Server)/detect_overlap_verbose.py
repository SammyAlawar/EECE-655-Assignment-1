#!/usr/bin/env python3
# detect_overlap_verbose.py
# Verbose fragment overlap detector that prints every fragment seen.

from scapy.all import sniff, IP, Raw
import argparse, time, threading, subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--iface", default="enp0s3")
parser.add_argument("--port", type=int, default=9999)
parser.add_argument("--block-on-detect", action="store_true")
parser.add_argument("--no-filter", action="store_true",
                    help="disable BPF filter (use only if other filters fail)")
args = parser.parse_args()

FRAG_TABLE = {}           # key: (src, dst, proto, id) -> list[(start, end, raw_bytes, ts)]
LOCK = threading.Lock()
EXPIRE_SECS = 120

def expire_old():
    while True:
        now = time.time()
        with LOCK:
            for k in list(FRAG_TABLE.keys()):
                entries = FRAG_TABLE.get(k, [])
                if not entries:
                    FRAG_TABLE.pop(k, None)
                    continue
                # entries[-1][3] is the timestamp of the newest fragment we saw for the flow
                if now - entries[-1][3] > EXPIRE_SECS:
                    FRAG_TABLE.pop(k, None)
        time.sleep(5)

def add_iptables_block(src_ip):
    try:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", src_ip, "-j", "DROP"], check=True)
        print("[MITIGATE] inserted iptables DROP for", src_ip)
    except Exception as e:
        print("[MITIGATE] failed:", e)

def handle_packet(pkt):
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    key = (ip.src, ip.dst, int(ip.proto), int(ip.id))

    # Fragment offset is in 8-byte blocks
    start = int(ip.frag) * 8

    # Payload bytes (safe even if Raw is absent)
    raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    end = start + len(raw)

    # MF flag display (robust across Scapy versions)
    # ip.flags might be an enum or a string; both cases handled:
    try:
        mf = 1 if getattr(ip.flags, "MF", False) else 0
    except Exception:
        mf = 1 if "MF" in str(ip.flags) else 0

    # Verbose line for every fragment
    print(
        f"[FRAG] {ip.src}->{ip.dst} id={ip.id} proto={ip.proto} "
        f"frag_off={ip.frag} start={start} end={end} MF={mf} "
        f"len={len(raw)}"
    )

    # Store and compare for overlaps
    now = time.time()
    with LOCK:
        entries = FRAG_TABLE.setdefault(key, [])
        entries.append((start, end, raw, now))

        # Compare the newest fragment (last) against previous ones
        s_new, e_new, d_new, _ = entries[-1]
        for (s_old, e_old, d_old, _ts) in entries[:-1]:
            # Overlap if not disjoint
            if not (e_new <= s_old or s_new >= e_old):
                ov_s = max(s_new, s_old)
                ov_e = min(e_new, e_old)
                if ov_e > ov_s:
                    b_new = d_new[ov_s - s_new : ov_e - s_new]
                    b_old = d_old[ov_s - s_old : ov_e - s_old]
                    if b_new != b_old:
                        print(">>> OVERLAP CONFLICT <<<")
                        print(" flow:", key)
                        print(" new frag:", (s_new, e_new))
                        print(" old frag:", (s_old, e_old))
                        print(" overlap bytes:", ov_s, ov_e, "len:", ov_e - ov_s)
                        print(" new(hex):", b_new[:64].hex(), "old(hex):", b_old[:64].hex())
                        if args.block_on_detect:
                            add_iptables_block(ip.src)
                        # Optional: clear flow after detection to limit spam
                        # FRAG_TABLE.pop(key, None)
                        return

        # Optional: if MF==0 and this looks like final fragment, you could clear the flow
        # to keep the table small once reassembly would be complete.
        # if mf == 0:
        #     FRAG_TABLE.pop(key, None)

if __name__ == "__main__":
    t = threading.Thread(target=expire_old, daemon=True)
    t.start()

    if args.no_filter:
        print("[+] starting detector (no BPF filter) on", args.iface)
        sniff(iface=args.iface, prn=handle_packet, store=False)
    else:
        # Match UDP to your port OR any fragmented IP (flags/offset non-zero)
        # ip[6:2] grabs the Flags+Fragment Offset field (16 bits).
        filter_str = f"ip and (udp port {args.port} or (ip[6:2] & 0x1fff != 0))"
        print("[+] starting detector on", args.iface, "filter:", filter_str)
        sniff(iface=args.iface, filter=filter_str, prn=handle_packet, store=False)
