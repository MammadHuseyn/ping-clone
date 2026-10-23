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

