"""IPv4 UDP entry point for the iterative DNS resolver"""

import argparse
import socket

from cache import Cache
from dnswire import SERVFAIL, Reply, WireError, encode_response, read_client_query
from resolver import ResolutionError, Resolver


def listen(handler):
    parser = argparse.ArgumentParser(description="IPv4 UDP DNS resolver")
    parser.add_argument("port", nargs="?", type=int, default=53)
    port = parser.parse_args().port
    if not 1 <= port <= 65535:
        parser.error("port must be between 1 and 65535")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", port))
        print(f"Listening on UDP port {port}", flush=True)
        while True:
            packet, client = sock.recvfrom(65535)
            try:
                response = handler(packet)
            except WireError:
                continue
            try:
                sock.sendto(response, client)
            except OSError as error:
                print(f"Could not send DNS response: {error}", flush=True)


class Handler:
    def __init__(self, resolver=None, cache=None):
        self.resolver = Resolver() if resolver is None else resolver
        self.cache = Cache() if cache is None else cache

    def __call__(self, packet):
        transaction_id, flags, question = read_client_query(packet)
        reply = self.cache.get(question)
        if reply is None:
            try:
                reply = self.resolver.resolve(question)
            except (ResolutionError, WireError):
                reply = Reply(SERVFAIL)
            self.cache.put(question, reply)

        return encode_response(question, transaction_id, flags, reply)


if __name__ == "__main__":
    listen(Handler())
