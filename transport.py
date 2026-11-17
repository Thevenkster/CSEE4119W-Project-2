"""UDP exchanges with upstream DNS servers"""

import secrets
import socket
import time

from dnswire import (
    OPCODE, QR, Reply, WireError, make_query, read_header, read_question,
    read_sections,
)


def ask_server(address, question, timeout):
    transaction_id = secrets.randbits(16)
    request = make_query(question, transaction_id)
    deadline = time.monotonic() + timeout

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((address, 53))
        sock.send(request)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("upstream DNS timeout")

            sock.settimeout(remaining)
            packet = sock.recv(65535)
            try:
                response_id, flags, questions, answers, authority, additional = read_header(packet)
                if response_id != transaction_id or not flags & QR:
                    continue
                if flags & OPCODE or questions != 1:
                    continue

                returned_question, offset = read_question(packet)
                if returned_question.key != question.key:
                    continue

                sections = read_sections(packet, offset, (answers, authority, additional))
                return Reply(flags, *sections)
            except WireError:
                continue
