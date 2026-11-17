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
