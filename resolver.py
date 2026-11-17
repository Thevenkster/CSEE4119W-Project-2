"""Iterative DNS resolution"""

from socket import inet_ntoa

from time import monotonic

from dnswire import (
    A, AA, ANY, CNAME, IN, NS, NXDOMAIN, RCODE, SOA, TC,
    Question, Reply, WireError, canonical, record_target,
)
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


def walk(question, budget, servers=ROOTS, zone=(), upstream=ask_server, resolve_address=None):
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
        addresses = delegation_addresses(nameservers, glue, resolve_address)

        try:
            return walk(question, budget, addresses, child_zone, upstream, resolve_address)
        except NoAnswer:
            continue

    raise NoAnswer("no usable authoritative DNS response")


def delegation_addresses(nameservers, glue, resolve_address):
    seen = set()
    for name in nameservers:
        for address in glue.get(name, ()):
            if address not in seen:
                seen.add(address)
                yield address

    if resolve_address is None:
        return

    for name in nameservers:
        if name in glue:
            continue
        for address in resolve_address(name):
            if address not in seen:
                seen.add(address)
                yield address


class Resolver:
    def __init__(self, roots=ROOTS, upstream=ask_server):
        self.roots = roots
        self.upstream = upstream

    def resolve(self, question):
        return self.lookup(question, Budget(), ())

    def addresses_for(self, name, budget, active):
        try:
            reply = self.lookup(Question(name, A, IN), budget, active)
        except NoAnswer:
            return ()
        if reply.flags & (TC | RCODE):
            return ()
        return tuple(
            inet_ntoa(record.data) for record in reply.answers
            if (record.rtype, record.rclass) == (A, IN) and len(record.data) == 4
        )

    def lookup(self, question, budget, ancestors):
        active = set(ancestors)
        chain = []
        current = question

        def resolve_address(name):
            return self.addresses_for(name, budget, active)

        while True:
            if current.key in active or len(active) >= 20:
                raise NoAnswer("DNS name dependency loop or excessive depth")
            active.add(current.key)
            sent_name = current.key[0]

            reply = walk(
                current, budget, self.roots, upstream=self.upstream,
                resolve_address=resolve_address,
            )
            code = reply.flags & RCODE
            if reply.flags & TC:
                return Reply(code | TC, tuple(chain))

            while True:
                matching = tuple(
                    record for record in reply.answers
                    if canonical(record.name) == current.key[0]
                    and class_matches(current, record)
                )
                direct = tuple(
                    record for record in matching
                    if current.qtype in (ANY, record.rtype)
                )
                if direct and code == 0:
                    return Reply(answers=tuple(chain) + direct)

                alias = next((record for record in matching if record.rtype == CNAME), None)
                if alias is None:
                    if current.key[0] == sent_name or code == NXDOMAIN:
                        authority = tuple(
                            record for record in reply.authority
                            if record.rtype == SOA and class_matches(current, record)
                        )
                        return Reply(code, tuple(chain), authority)
                    break

                chain.append(alias)
                current = Question(record_target(alias), current.qtype, current.qclass)
                if current.key in active or len(chain) >= 16:
                    raise NoAnswer("CNAME loop or excessive chain length")

                supplied = any(
                    canonical(record.name) == current.key[0]
                    and class_matches(current, record)
                    for record in reply.answers
                )
                if not supplied and code != NXDOMAIN:
                    break
                active.add(current.key)
