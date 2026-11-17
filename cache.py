"""In-memory cache for positive DNS replies"""

from dataclasses import replace
from time import monotonic

from dnswire import RCODE, SOA, TC


class Cache:
    def __init__(self, clock=monotonic):
        self.clock = clock
        self.entries = {}

    def put(self, question, reply):
        if reply.flags & (RCODE | TC) or not reply.answers:
            return
        if any(record.rtype == SOA for record in reply.authority):
            return

        records = reply.answers + reply.authority + reply.additional
        ttl = min(record.ttl for record in records)
        if ttl > 0:
            now = self.clock()
            self.entries[question.key] = (now, now + ttl, reply)

    def get(self, question):
        entry = self.entries.get(question.key)
        if entry is None:
            return None

        stored, expires, reply = entry
        now = self.clock()
        if now >= expires:
            del self.entries[question.key]
            return None

        elapsed = int(now - stored)

        def age(records):
            return tuple(replace(record, ttl=record.ttl - elapsed) for record in records)

        return replace(
            reply,
            answers=age(reply.answers),
            authority=age(reply.authority),
            additional=age(reply.additional),
        )
