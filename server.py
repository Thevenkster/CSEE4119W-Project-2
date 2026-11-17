"""IPv4 UDP listener for the DNS resolver"""

import argparse
import socket

from dnswire import WireError, read_client_query


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
            if response is not None:
                sock.sendto(response, client)


def log_query(packet):
    transaction_id, _, question = read_client_query(packet)
    print(f"Received query {transaction_id}: {question}", flush=True)


if __name__ == "__main__":
    listen(log_query)
