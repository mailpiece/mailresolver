# Changelog

## Unreleased

- `nameservers:` option, to ask given addresses instead of the system resolver.
- Advertise a 1232-byte EDNS buffer, not dnsruby's 4096.
- Raise `Timeout` at the deadline even when dnsruby's I/O thread is stuck.
- Don't lose replies to a burst of queries on a fresh resolver.
- Raise `ServerFailure` on an rcode dnsruby doesn't know, or a reply still truncated.
- Raise `NoSuchName` for a name DNS can't carry, without asking, and `ArgumentError` for `nil`.
- Answer only with records owned by the name asked or an alias it leads to; `cname` answers with the first alias.
- Quote the name in error messages, so a CR, LF or NUL in it is escaped.
- Raise `ArgumentError` on construction for timeouts that aren't positive numbers, or no nameservers.
- Accept `IPAddr` nameservers, and refuse a range rather than masking it to its first address.
- `with_deadline`, for a resolver whose queries are cut to end by a deadline.
- README: TCP/53 must be reachable, and when to share a resolver.

## 0.6.0

- `ns` lookup, on the resolver and the fake.

## 0.5.1

- Re-release: 0.5.0

## 0.5.0

- Initial public release.
