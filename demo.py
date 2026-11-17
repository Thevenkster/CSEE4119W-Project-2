from socket import inet_aton

from dnswire import A, IN, Record, Reply, encode_response, read_client_query
from server import listen


def fixed_answer(packet):
    transaction_id, flags, question = read_client_query(packet)
    answers = ()
    if (question.qtype, question.qclass) == (A, IN):
        answer = Record(question.name, A, IN, 30, inet_aton("192.0.2.10"))
        answers = (answer,)

    return encode_response(question, transaction_id, flags, Reply(answers=answers))


if __name__ == "__main__":
    listen(fixed_answer)
