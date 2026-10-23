import os
import socket
import struct
import sys
import time

from ping import build_packet

MAX_HOPS = 30
PROBES_PER_HOP = 3
TIMEOUT = 2.0

def probe(sock, dest_ip, ident, seq, ttl):
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl) #sets ipv4 ttl packets though this socket
    sock.sendto(build_packet(ident, seq), (dest_ip, 0)) #send echo req

    start  = time.time()

    while True:
        remaning = TIMEOUT - (time.time()-start)
        if remaning<=0:
            return None
        sock.settimeout(remaning)
        try:
            data, addr = sock.recvfrom(1024) #wait for packet
        except socket.timeout:
            return None

        rtt = (time.time()- start) * 1000

        if len(data) < 20: #ipv4 header is atleast 20bytes
            continue
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 8: #being sure that packet contains full icmp header
            continue
        icmp_type = data[ihl]
        #print(f"  [debug] type={icmp_type} from {addr[0]}")

        if icmp_type == 0:
            #echo reply
            echo_id, echo_seq = struct.unpack(
                "!HH", data[ihl + 4:ihl + 8] #16 bit values
            )
            if echo_id == ident and echo_seq == seq: 
                #accepts the echo reply only if it belongs to the current probe
                return 0, addr[0], rtt
            continue

        if icmp_type == 11:
            #time exceed (hops)
            # The payload quotes the original IP packet and its ICMP header.

            quoted_ip_offset = ihl + 8 #outer icmp header is 8bytes long
            if len(data) < quoted_ip_offset + 20:
                continue
            quoted_ihl = (data[quoted_ip_offset] & 0x0F) * 4
            quoted_icmp_offset = quoted_ip_offset + quoted_ihl 
            #where the ofiginal probes icmp header begin
            if len(data) < quoted_icmp_offset + 8:
                continue
            quoted_type, _, _, quoted_id, quoted_seq = struct.unpack(
                #_ -> original
                "!BBHHH", data[quoted_icmp_offset:quoted_icmp_offset + 8]
            )

            if (
                quoted_type == 8
                and quoted_id == ident
                and quoted_seq == seq
            ):
                return 11, addr[0], rtt

def main():
    if len(sys.argv) != 2:
        sys.exit("usage: sudo python3 traceroute.py <host>")

    host = sys.argv[1] #example.com
    dest_ip = socket.gethostbyname(host) #resolve an ipv4 addr
    ident = os.getpid() & 0xFFFF #return current process id and keeps only lower 16 bits

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print(f"traceroute to {host} ({dest_ip}), max {MAX_HOPS} hops")

    for ttl in range(1, MAX_HOPS+1):
        results = []
        reached_destination = False
        for probe_number in range(PROBES_PER_HOP):
            seq = (ttl - 1) * PROBES_PER_HOP + probe_number + 1
            #this generates uniqe sequence
            result = probe(sock, dest_ip, ident, seq=seq, ttl=ttl)
            results.append(result)
            if result is not None and result[0] == 0:
                reached_destination = True

        routers = {result[1] for result in results if result is not None} #set of router adds, without timeouts
        output = next(iter(routers)) if len(routers) == 1 else ""
        for result in results:
            if result is None:
                output += "  *"
            elif len(routers) == 1:
                output += f"  {result[2]:.1f} ms"
            else:
                output += f"  {result[1]} {result[2]:.1f} ms"
        print(f"{ttl:2d} {output}")

        if reached_destination:
            break

if __name__ == "__main__":
    main()