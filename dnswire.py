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


# Each layout gives the prefix length, name count, and trailing byte count
# None allows variable trailing data after the final name
RDATA_NAME_LAYOUTS = {
    NS: (0, 1, 0),
    3: (0, 1, 0),   # MD
    4: (0, 1, 0),   # MF
    CNAME: (0, 1, 0),
    SOA: (0, 2, 20),
    7: (0, 1, 0),   # MB
    8: (0, 1, 0),   # MG
    9: (0, 1, 0),   # MR
    12: (0, 1, 0),  # PTR
    14: (0, 2, 0),  # MINFO
    MX: (2, 1, 0),
    17: (0, 2, 0),  # RP
    18: (2, 1, 0),  # AFSDB
    21: (2, 1, 0),  # RT
    24: (18, 1, None),  # SIG
    26: (2, 2, 0),  # PX
    30: (0, 1, None),  # NXT
    33: (6, 1, 0),  # SRV
    36: (2, 1, 0),  # KX
    39: (0, 1, 0),  # DNAME
}


def normalize_data(packet, start, end, rtype, rclass):
    if rtype == A and rclass == IN and end - start != 4:
        raise WireError("invalid IPv4 record length")

    layout = RDATA_NAME_LAYOUTS.get(rtype)
    if rtype == 35:  # NAPTR
        position = start + 4
        for _ in range(3):
            if position >= end:
                raise WireError("short NAPTR character string")
            position += packet[position] + 1
        layout = (position - start, 1, 0)

    if layout is None:
        return packet[start:end]

    prefix, name_count, tail = layout
    position = start + prefix
    if position >= end:
        raise WireError("missing name in resource data")

    chunks = [packet[start:position]]
    for _ in range(name_count):
        name, position = read_name(packet, position, end)
        chunks.append(encode_name(name))

    if tail is not None and end - position != tail:
        raise WireError("invalid resource data layout")
    chunks.append(packet[position:end])
    return b"".join(chunks)


def read_record(packet, offset):
    name, rtype, rclass, ttl, start, end = record_bounds(packet, offset)
    data = normalize_data(packet, start, end, rtype, rclass)
    return Record(name, rtype, rclass, ttl, data), end


def record_target(record):
    name, _ = read_name(record.data, 0)
    return name
