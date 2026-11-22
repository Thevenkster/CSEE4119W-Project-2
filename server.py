"""IPv4 UDP entry point for the iterative DNS resolver"""

import argparse
import socket
import sys
from struct import Struct

from cache import Cache
from dnswire import SERVFAIL, Reply, WireError, encode_response, read_client_query
from resolver import ResolutionError, Resolver


# Linux uses option 8 even on Python builds without the named constant
IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8) if sys.platform.startswith("linux") else None
PACKET_INFO = Struct("=I4s4s")


def receive_query(sock):
    if IP_PKTINFO is None:
        packet, client = sock.recvfrom(65535)
        return packet, client, []

    packet, metadata, _, client = sock.recvmsg(65535, socket.CMSG_SPACE(PACKET_INFO.size))
    for level, kind, data in metadata:
        if level == socket.IPPROTO_IP and kind == IP_PKTINFO:
            _, _, destination = PACKET_INFO.unpack(data)
            reply_info = PACKET_INFO.pack(0, destination, bytes(4))
            return packet, client, [(level, kind, reply_info)]
    return packet, client, []


def listen(handler):
    parser = argparse.ArgumentParser(description="IPv4 UDP DNS resolver")
    parser.add_argument("port", nargs="?", type=int, default=53)
    port = parser.parse_args().port
    if not 1 <= port <= 65535:
        parser.error("port must be between 1 and 65535")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if IP_PKTINFO is not None:
            sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
        sock.bind(("0.0.0.0", port))
        print(f"Listening on UDP port {port}", flush=True)
        while True:
            packet, client, reply_source = receive_query(sock)
            try:
                response = handler(packet)
            except WireError:
                continue
            try:
                if reply_source:
                    sock.sendmsg([response], reply_source, 0, client)
                else:
                    sock.sendto(response, client)
            except OSError as error:
                print(f"Could not send DNS response: {error}", flush=True)


class Handler:
    def __init__(self, resolver=None, cache=None):
        self.resolver = Resolver() if resolver is None else resolver
        self.cache = Cache() if cache is None else cache

    def __call__(self, packet):
        transaction_id, flags, question, edns_size = read_client_query(packet)
        reply = self.cache.get(question)
        if reply is None:
            try:
                reply = self.resolver.resolve(question)
            except (ResolutionError, WireError):
                reply = Reply(SERVFAIL)
            self.cache.put(question, reply)

        return encode_response(
            question, transaction_id, flags, reply, edns_size=edns_size,
        )


if __name__ == "__main__":
    listen(Handler())
