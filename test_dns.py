import unittest
from socket import inet_aton
from unittest.mock import Mock

from cache import Cache
from dnswire import (
    A, AA, IN, NS, NXDOMAIN, RCODE, RD, SOA, TC,
    Question, Record, Reply, WireError, encode_name, make_query,
    read_header, read_question, read_sections,
)
from resolver import Resolver
from server import Handler

NAME = (b"example", b"com")
QUESTION = Question(NAME, A, IN)


def ipv4(name, address, ttl=60):
    return Record(name, A, IN, ttl, inet_aton(address))


def nameserver(zone, target):
    return Record(zone, NS, IN, 60, encode_name(target))


class ResolverTests(unittest.TestCase):
    def test_truncated_root_referral_still_leads_to_an_answer(self):
        root, tld, authority = "192.0.2.1", "192.0.2.2", "192.0.2.3"
        tld_name = (b"ns", b"gtld", b"net")
        authority_name = (b"ns", b"provider", b"com")
        answer = ipv4(NAME, "192.0.2.40")
        responses = {
            root: Reply(
                TC,
                authority=(nameserver((b"com",), tld_name),),
                additional=(ipv4(tld_name, tld),),
            ),
            tld: Reply(
                authority=(nameserver(NAME, authority_name),),
                additional=(ipv4(authority_name, authority),),
            ),
            authority: Reply(AA, answers=(answer,)),
        }
        upstream = Mock(side_effect=lambda address, question, timeout: responses[address])

        reply = Resolver((root,), upstream).resolve(QUESTION)

        self.assertEqual(reply.answers, (answer,))
        self.assertEqual([call.args[0] for call in upstream.call_args_list], [root, tld, authority])

    def test_malformed_queries_never_reach_the_resolver(self):
        resolver = Mock()
        handler = Handler(resolver=resolver)
        for packet in (b"", make_query(QUESTION, 42)[:-1], make_query(QUESTION, 42) + b"\0"):
            with self.subTest(packet=packet), self.assertRaises(WireError):
                handler(packet)
        resolver.resolve.assert_not_called()

    def test_cache_preserves_client_id_and_expires(self):
        now = [100.0]
        resolver = Mock()
        resolver.resolve.return_value = Reply(answers=(ipv4(NAME, "192.0.2.40", ttl=4),))
        handler = Handler(resolver=resolver, cache=Cache(clock=lambda: now[0]))

        handler(make_query(QUESTION, 11, RD))
        now[0] = 102.0
        packet = handler(make_query(QUESTION, 12, RD))
        self.assertEqual(read_header(packet)[0], 12)
        _, offset = read_question(packet)
        answers, _, _ = read_sections(packet, offset, (1, 0, 0))
        self.assertEqual(answers[0].ttl, 2)
        resolver.resolve.assert_called_once_with(QUESTION)

        now[0] = 104.0
        handler(make_query(QUESTION, 13, RD))
        self.assertEqual(resolver.resolve.call_count, 2)

    def test_nxdomain_keeps_soa_and_is_not_cached(self):
        soa = Record(NAME, SOA, IN, 60, b"\0\0" + bytes(20))
        upstream = Mock(return_value=Reply(AA | NXDOMAIN, authority=(soa,)))
        handler = Handler(resolver=Resolver(("192.0.2.1",), upstream))

        for transaction_id in (21, 22):
            packet = handler(make_query(QUESTION, transaction_id, RD))
            _, flags, _, answers, authority, additional = read_header(packet)
            self.assertEqual(flags & RCODE, NXDOMAIN)
            _, offset = read_question(packet)
            self.assertEqual(
                read_sections(packet, offset, (answers, authority, additional)),
                ((), (soa,), ()),
            )

        self.assertEqual(upstream.call_count, 2)


if __name__ == "__main__":
    unittest.main()
