"""Iterative DNS resolution"""

from socket import inet_ntoa

from dnswire import A, ANY, IN, NS, canonical, record_target


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
