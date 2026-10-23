import os
import socket
import struct
import sys
import time


ICMP_ECHO_REQUEST = 8 #outgoing ping
ICMP_ECHO_REPLY = 0


def checksum(data: bytes) -> int:

    if len(data) %2: #adding padding, cause checksum processes data in 2-byte groups
        data+=  b"\x00"
    total = 0
    for i in range(0, len(data), 2): #reading two bytes at time
        #byte packing
        total += (data[i] << 8) + data[i+1] #2bytes become one 16 bit number
        # 0x12 << 8 = 0x1200
        # 0x1200 + 0x34 = 0x1234
    total = (total >> 16) + (total & 0xFFFF)
    #if sum exceeds 16 bits, oveflow is wrapped and added back to lower 16bits
    total += total >> 16
    #second possible carry
    return ~total & 0xFFFF
    #~ flips every bit.
    #0xFFFF keeps only the lowest 16 bits

def build_packet(ident: int, seq: int) -> bytes:
    """ ICMP header (type(1), code(1), checksum(2), id(2) , seq(2)) + payload"""

    payload = struct.pack("!d", time.time()) + b"abcdefgh" 
    # 8byte timestamp + 8bytes of text

    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq) #initial header
    csum = checksum(header+payload)
    #checksum is initially zero because the checksum itself must be excluded
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST,0 ,csum, ident, seq)
    return header +payload #8bytes + 16bytes | complete packet

def ping_once(sock, dest_ip, ident, seq, timeout=2.0):
    sock.sendto(build_packet(ident,seq), (dest_ip, 0))
    #build icmp echo request
    #it uses port 0, because icmp doesnt use tcp\udp ports
    start = time.time() #for rtt
    while True:
        remaining = timeout - (time.time() - start)
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        #settimeout tells socket how long should it wait
        try:
            data, addr = sock.recvfrom(1024) #wait for a packet of up to 1024 bytes
        except socket.timeout:
            return None
        rtt =(time.time()-start)*1000 #converted from second to ms

        ihl = (data[0] & 0x0F) *4 #shows where payload is beings
        # & 0x0F extracts lower four bits, it is measured in bits, *4 convert to bytes

            #   0100 0101   <- data[0] (Version + IHL)
            # & 0000 1111   <- 0x0F    (The Mask)
        
            #   0000 0101   <- Result  (Version is erased; only IHL remains)
            
        ttl = data[8] #8th bytes of the IPv4 header is ttl

        #extractring 8-byte icmp header
        icmp_type, _code, _csum, r_id, r_seq = struct.unpack("!BBHHH", data[ihl:ihl + 8])

        # Ignore other ICMP traffic; only accept the reply to our request
        if icmp_type == ICMP_ECHO_REPLY and r_id == ident and r_seq == seq:
            return rtt, ttl, addr[0]

def main():
    if len(sys.argv) != 2: #len must be 2
        sys.exit("usage: sudo python3 ping.py <host>")

    #argv = ping.py example.com

    host = sys.argv[1] #example.com
    dest_ip = socket.gethostbyname(host) #resolve an ipv4 addr
    ident = os.getpid() & 0xFFFF #return current process id and keeps only lower 16 bits

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    #creating raw icmp soket
    #AF_INET - IPv4
    #SOCK_RAW - access to raw packet data
    #IPPROTO_ICMP - icmp protocol

    print(f"Pinging <3 {host} ({dest_ip})")

    for seq in range(1,5): #sending four ping requests
        result = ping_once(sock, dest_ip, ident, seq) #sends packet and waits 2 second
        if result is None:
            print(f"seq={seq}: request timed out")
        else: #unpacks valuest and prints
            rtt, ttl, src = result
            print(f"reply from {src}: seq={seq} ttl={ttl} time={rtt:.1f} ms")

        time.sleep(1) #waits 1 sec before sending another

if __name__ == "__main__":
    main()