"""DNS message parsing and serialization"""

from dataclasses import dataclass
from struct import Struct

HEADER = Struct("!6H")
QUESTION = Struct("!2H")
RR_HEADER = Struct("!2HIH")
U16 = Struct("!H")

QR, AA, TC, RD, RA, CD = 0x8000, 0x0400, 0x0200, 0x0100, 0x0080, 0x0010
OPCODE, RCODE = 0x7800, 0x000F
A, NS, CNAME, SOA, MX, OPT, ANY = 1, 2, 5, 6, 15, 41, 255
IN, SERVFAIL, NXDOMAIN = 1, 2, 3
UDP_LIMIT = 512


class WireError(ValueError):
    pass


@dataclass(frozen=True)
class Question:
    name: tuple
    qtype: int
    qclass: int

    @property
    def key(self):
        return canonical(self.name), self.qtype, self.qclass


@dataclass(frozen=True)
class Record:
    name: tuple
    rtype: int
    rclass: int
    ttl: int
    data: bytes


@dataclass(frozen=True)
class Reply:
    flags: int = 0
    answers: tuple = ()
    authority: tuple = ()
    additional: tuple = ()


def read_header(packet):
    if len(packet) < HEADER.size:
        raise WireError("short DNS header")
    return HEADER.unpack_from(packet)


def canonical(name):
    return tuple(label.lower() for label in name)


def encode_name(name):
    if any(not 1 <= len(label) <= 63 for label in name):
        raise WireError("invalid DNS label length")
    if sum(len(label) + 1 for label in name) + 1 > 255:
        raise WireError("DNS name exceeds 255 bytes")
    return b"".join(bytes((len(label),)) + label for label in name) + b"\0"


def read_name(packet, offset, limit=None):
    if limit is None:
        limit = len(packet)

    labels = []
    visited = set()
    resume = None
    expanded_length = 1

    while True:
        if not 0 <= offset < limit or offset in visited:
            raise WireError("invalid DNS name or compression loop")
        visited.add(offset)
        size = packet[offset]

        if size == 0:
            if resume is None:
                resume = offset + 1
            return tuple(labels), resume

        if (size & 0xC0) == 0xC0:
            if offset + 1 >= limit:
                raise WireError("short compression pointer")
            target = ((size & 0x3F) << 8) | packet[offset + 1]
            if not HEADER.size <= target < offset:
                raise WireError("invalid compression target")
            if resume is None:
                resume = offset + 2
            offset = target
            limit = len(packet)
            continue

        end = offset + 1 + size
        if size > 63 or end > limit:
            raise WireError("invalid DNS label")
        expanded_length += size + 1
        if expanded_length > 255:
            raise WireError("expanded DNS name exceeds 255 bytes")
        labels.append(packet[offset + 1:end])
        offset = end


def read_question(packet, offset=HEADER.size):
    name, offset = read_name(packet, offset)
    end = offset + QUESTION.size
    if end > len(packet):
        raise WireError("short DNS question")
    qtype, qclass = QUESTION.unpack_from(packet, offset)
    return Question(name, qtype, qclass), end


def make_query(question, transaction_id, flags=0):
    header = HEADER.pack(transaction_id, flags, 1, 0, 0, 0)
    name = encode_name(question.name)
    fields = QUESTION.pack(question.qtype, question.qclass)
    return header + name + fields


def record_bounds(packet, offset):
    name, offset = read_name(packet, offset)
    start = offset + RR_HEADER.size
    if start > len(packet):
        raise WireError("short resource record header")

    rtype, rclass, ttl, size = RR_HEADER.unpack_from(packet, offset)
    end = start + size
    if end > len(packet):
        raise WireError("resource data exceeds packet length")

    return name, rtype, rclass, ttl, start, end
