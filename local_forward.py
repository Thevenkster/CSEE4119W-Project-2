import socket

from dnswire import QR, RD, make_query, read_client_query, read_header
from server import listen

COLUMBIA_RESOLVER = ("128.59.1.3", 53)


def forward(packet):
    transaction_id, _, question = read_client_query(packet)
    upstream_query = make_query(question, transaction_id, RD)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.connect(COLUMBIA_RESOLVER)
            sock.send(upstream_query)
            reply = sock.recv(65535)
    except OSError:
        return None

    response_id, flags, *_ = read_header(reply)
    if response_id == transaction_id and flags & QR:
        return reply
    return None


if __name__ == "__main__":
    listen(forward)
