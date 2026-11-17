"""Iterative DNS resolution"""

from socket import inet_ntoa

from time import monotonic

from dnswire import A, AA, ANY, IN, NS, NXDOMAIN, RCODE, WireError, canonical, record_target
from roots import ROOTS
from transport import ask_server


def within(name, zone):
    return not zone or name[-len(zone):] == zone


def class_matches(question, record):
    return question.qclass in (ANY, record.rclass)


def referral(question, authority, current_zone):
    name = question.key[0]
    candidates = {}

    for record in authority:
        if record.rtype != NS or not class_matches(question, record):
            continue

        zone = canonical(record.name)
        if len(zone) <= len(current_zone) or not within(zone, current_zone):
            continue
        if within(name, zone):
            target = canonical(record_target(record))
            candidates.setdefault(zone, []).append(target)

    if not candidates:
        return None

    zone = max(candidates, key=len)
    return zone, tuple(dict.fromkeys(candidates[zone]))


def glue_addresses(nameservers, additional, current_zone):
    addresses = {}
    for record in additional:
        if (record.rtype, record.rclass) != (A, IN) or len(record.data) != 4:
            continue

        owner = canonical(record.name)
        if owner not in nameservers or not within(owner, current_zone):
            continue

        address = inet_ntoa(record.data)
        known = addresses.setdefault(owner, [])
        if address not in known:
            known.append(address)
    return addresses


class ResolutionError(Exception):
    pass


class NoAnswer(ResolutionError):
    pass


class BudgetExceeded(ResolutionError):
    pass


class Budget:
    def __init__(self):
        self.deadline = monotonic() + 6
        self.remaining = 48

    def next_timeout(self):
        seconds_left = self.deadline - monotonic()
        if seconds_left <= 0 or self.remaining <= 0:
            raise BudgetExceeded("upstream DNS lookup budget exhausted")
        self.remaining -= 1
        return min(seconds_left, 1)


def walk(question, budget, servers=ROOTS, zone=(), upstream=ask_server):
    for server in servers:
        timeout = budget.next_timeout()
        try:
            reply = upstream(server, question, timeout)
        except (OSError, WireError):
            continue

        code = reply.flags & RCODE
        if reply.flags & AA and code in (0, NXDOMAIN):
            return reply
        if code:
            continue

        delegation = referral(question, reply.authority, zone)
        if delegation is None:
            continue

        child_zone, nameservers = delegation
        glue = glue_addresses(nameservers, reply.additional, zone)
        addresses = tuple(dict.fromkeys(
            address for name in nameservers for address in glue.get(name, ())
        ))

        try:
            return walk(question, budget, addresses, child_zone, upstream)
        except NoAnswer:
            continue

    raise NoAnswer("no usable authoritative DNS response")
