# CSEE4119W Project 2

An iterative DNS resolver written in Python using IPv4 UDP and the standard library

## Run the resolver

```sh
python3 -u server.py 10075
```

The optional port argument defaults to 53. Port `10075` is the assigned port on compute08

## Test the resolver

Run the offline tests from the project directory

```sh
python3 -m unittest -v
```

From a second terminal on compute08, query the running server

```sh
dig @127.0.0.1 -p 10075 example.com A
dig @127.0.0.1 -p 10075 gmail.com MX
```

From a machine that can reach compute08, query the assigned endpoint

```sh
dig @compute08.cs.columbia.edu -p 10075 example.com A
```

## How it works

- Starts uncached queries at an IANA IPv4 root server with the recursion-desired bit cleared
- Follows nameserver referrals, looks up missing nameserver addresses, and follows CNAMEs
- Caches positive replies by name, type, and class until the earliest record TTL expires
- Drops malformed client queries and marks truncated UDP replies with the TC flag
