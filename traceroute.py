import os
import socket
import sys
import time

from ping import build_packet

MAX_HOPS = 30
TIMEOUT = 2.0

def probe(sock, dest_ip, ident, seq, ttl):
    #send 1 packet with specific ttl

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

        ihl = (data[0] & 0x0F) * 4
        icmp_type = data[ihl]
        #print(f"  [debug] type={icmp_type} from {addr[0]}")

        if icmp_type == 0:
            #echo reply
            return 0, addr[0], rtt

        if icmp_type == 11:
            #time exceed (hops)

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
        result  = probe(sock,dest_ip, ident, seq = ttl, ttl=ttl) #sends probe: seq number is ttl, and ttl is current hop number
        if result is None:
            print(f"{ttl:2d}  * (timeout)")
            continue
        icmp_type, router_ip, rtt = result
        print(f"{ttl:2d}  {router_ip}  {rtt:.1f} ms")

        if icmp_type == 0:
            break

if __name__ == "__main__":
    main()