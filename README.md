# mailresolver

🔍 DNS resolution for mail, in Ruby.

**mailresolver** is a small, injectable DNS client for mail libraries — TXT, A/AAAA, MX, PTR, CNAME, and NS lookups.

For mail libraries and the apps that use them: SPF/DKIM/DMARC/MTA-STS checks that need a missing record told apart from a server that couldn't answer, apps running several mail libraries that want one shared resolver instead of one apiece, test suites that want to fake DNS without touching a network.

**mailresolver** handles:

- TXT, A, AAAA, MX, PTR, CNAME, and NS lookups, plus a merged `addresses` for A+AAAA
- a three-way error taxonomy — `NotFound`, `ServerFailure`, `Timeout` — instead of collapsing every failure into an empty answer
- one shared resolver across every mail library in your app, multiplexed over dnsruby's single I/O thread
- configurable retry/timeout schedule
- DNSSEC validation and answer caching off, unconditionally, for callers that have no way to act on either
- test doubles — a hash-backed fake and a real loopback nameserver — so a suite never needs the network

> Not a general-purpose DNS client — six record types and three errors, built for what mail authentication needs.

## Contents

- [Installation](#installation)
- [Usage](#usage)
- [The Error Taxonomy](#the-error-taxonomy)
- [Why This Distinction Exists](#why-this-distinction-exists)
- [One Resolver, Shared](#one-resolver-shared)
- [Configuration](#configuration)
- [Custom Resolvers](#custom-resolvers)
- [Test Doubles](#test-doubles)
- [Testing](#testing)
- [History](#history)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Installation

Add this line to your application's Gemfile:

```ruby
gem "mailresolver"
```

Requires Ruby >= 3.4

## Usage

```ruby
require "mailresolver"

resolver = MailResolver::Resolver.new

resolver.txt("example.com")           # => ["v=spf1 -all"]
resolver.a("example.com")             # => ["203.0.113.10"]
resolver.aaaa("example.com")          # => ["2001:db8::1"]
resolver.addresses("example.com")     # => ["203.0.113.10", "2001:db8::1"]
resolver.mx("example.com")            # => ["mx1.example.com", "mx2.example.com"], sorted by preference
resolver.ptr("203.0.113.10")          # => ["mail.example.com"]
resolver.cname("www.example.com")     # => ["example.com"]
resolver.ns("example.com")            # => ["ns1.example.net", "ns2.example.net"]
```

`MailResolver::Resolver.new(nameservers: ["192.0.2.53", "2001:db8::53"])` asks those addresses, strings or `IPAddr`s, instead of the system resolver; one that isn't a single address raises `ServerFailure`, and an empty list `ArgumentError`.

`addresses` merges A and AAAA. A family the name doesn't publish contributes nothing to it rather than ending the lookup — but a name that doesn't exist at all raises `NoSuchName`, and a nameserver that couldn't answer still raises, same as every other method here.

IPv6 addresses come back lower case: dnsruby renders them upper case, and RFC 5952 §4.3 asks for lower.

## The Error Taxonomy

Every method raises one of three errors instead of guessing:

- `MailResolver::NotFound` — the server said there is nothing there: NXDOMAIN, or NOERROR with no records of the type asked for. NXDOMAIN specifically raises the subclass `MailResolver::NoSuchName`, for the callers — implicit MX, for one — to whom "the name doesn't exist" means something different from "the name has no records of this type"
- `MailResolver::ServerFailure` — the server didn't say: SERVFAIL, REFUSED, or a transport failure (a connect that failed, a socket dnsruby couldn't open, an address that wouldn't resolve)
- `MailResolver::Timeout` — no answer arrived in time

All of them descend from `MailResolver::Error`. A name DNS can't carry — empty, an empty label, a label over 63 bytes, over 253 in all, or any backslash — raises `NoSuchName` without a query, since no such name can exist. Other malformed input is the caller's bug, not a DNS answer, and raises `ArgumentError` instead — `ptr("not an ip")`, or a `nil` name.

## Why This Distinction Exists

`NotFound` and `ServerFailure` look interchangeable from a distance — both mean "I don't have an answer for you" — but they mean opposite things to the caller, and mail authentication is built on the difference.

SPF (RFC 7208) counts a void lookup — a `NotFound` — against its ten-lookup budget and keeps evaluating. It abandons evaluation entirely on a `ServerFailure` or a `Timeout`, returning `temperror` rather than pretending the record said nothing. Collapse the two, the way `Resolv` does, and a nameserver having a bad minute reads as a domain that designates no senders — SPF fails a message that should have deferred, and a forged one passes for the same reason a legitimate one would have failed.

The same shape recurs in DKIM, DMARC, and MTA-STS: a missing record is a policy decision the domain made; a server that couldn't answer is not.

## One Resolver, Shared

Build one `MailResolver::Resolver` and hand it to every mail library your app uses:

```ruby
resolver = MailResolver::Resolver.new

MailAuth.authenticate(raw, ip: ip, resolver: resolver)
MtaSts.lookup(domain, known: nil, resolver: resolver)
```

A resolver is safe to share across threads. dnsruby sends every query in the process over one I/O thread, whichever resolver it came from, so a resolver apiece costs no thread, only building dnsruby's resolver again — reading the system configuration — on each one's first query. Share one by default, and give a lookup with a deadline of its own a resolver from `with_deadline`, which asks over the same one: see [Deadlines](#deadlines).

That one I/O thread is also why TCP matters: see [Configuration](#configuration).

## Configuration

```ruby
MailResolver::Resolver.new(timeouts: [5, 3, 3])
```

`timeouts` is one attempt per element: the first element is how long the first packet gets before the first retry, dnsruby doubles the interval for each retry after that, and the sum is the deadline. The default sends packets at 0, 5, and 10 seconds and gives the whole query 11 seconds before raising `Timeout`. dnsruby checks deadlines twice a second, so a lookup can run up to half a second over, but no more, even when dnsruby's I/O thread is stuck.

The nameserver must be reachable on TCP port 53 as well as UDP. An answer over 1232 bytes comes back truncated and dnsruby asks again over TCP, connecting from its one I/O thread: if TCP/53 is filtered, that connect blocks every lookup in the process for up to the first timeout. Each still raises `Timeout` at its own deadline.

DNSSEC validation and dnsruby's answer cache are both off, unconditionally. DNSSEC costs a round trip that most callers of this gem have no way to act on — MTA-STS, for one, trusts the certificate on the policy host rather than the DNS answer. Caching is dnsruby's own concern to have off: its cache is process-global, so a nameserver that starts failing would otherwise keep serving its last good answer to every caller in the process.

### Deadlines

```ruby
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 8
resolver.with_deadline(deadline).ptr("203.0.113.10")
```

By default a query has its whole schedule, however long its caller has. `with_deadline(at)` returns a resolver for a caller that must be done by `at`, a `CLOCK_MONOTONIC` time: each query's timeouts are scaled down to the time left, keeping their proportions, and once `at` has passed every query raises `Timeout` without being sent. It asks over the resolver it came from, so it costs no new dnsruby resolver, and the resolver it came from keeps its own schedule. A TCP connect still gets the first timeout in full; the caller still gets `Timeout` by `at`, plus the half second above.

## Custom Resolvers

Anything that responds to `txt`, `a`, `aaaa`, `addresses`, `mx`, `ptr`, `cname`, and `ns` — raising the three errors above — is a drop-in replacement. You don't have to write one: see [Test Doubles](#test-doubles).

## Test Doubles

`MailResolver::Testing` ships what every caller's suite would otherwise hand-roll. It isn't loaded with the gem:

```ruby
require "mailresolver/testing"
```

`FakeResolver` stands a hash in for a zone, no network involved:

```ruby
resolver = MailResolver::Testing::FakeResolver.new(
  "example.com"  => { txt: [ "v=spf1 -all" ], a: [ "192.0.2.1" ] },
  "broken.example.com" => { txt: :servfail }
)

resolver.txt("example.com")          # => ["v=spf1 -all"]
resolver.mx("example.com")           # raises NotFound — the name is here, MX isn't
resolver.txt("absent.example.com")   # raises NoSuchName — the name isn't here at all
resolver.txt("broken.example.com")   # raises ServerFailure
resolver.queries                     # => [["example.com", :txt], ...]
```

The sentinels `:timeout`, `:servfail`, and `:nxdomain` stand where records would, for the failures a zone can't otherwise express. PTR is keyed by the address itself rather than its reverse name.

`LocalNameserver` goes a layer lower, for the cases a double can only assert by decree — what dnsruby actually raises per rcode. It binds a UDP socket on loopback, answers every query with the rcode you name, and hands you a `Resolver` pointed at it:

```ruby
MailResolver::Testing::LocalNameserver.answering(:servfail) do |resolver|
  assert_raises(MailResolver::ServerFailure) { resolver.txt("example.com") }
end
```

`:noerror`, `:servfail`, `:nxdomain`, and `:refused` are the rcodes; `nil` never replies, which is what a timeout looks like from the client. Pass `records:` to answer a `:noerror` query.

## Testing

```sh
bundle install
rake
```

The suite stubs `Dnsruby::Resolver`'s query path throughout.

## History

View the [changelog](CHANGELOG.md).

## Contributing

Everyone is encouraged to help improve this project:

- [Report bugs](https://github.com/mailpiece/mailresolver/issues)
- Fix bugs and submit pull requests
- Write, clarify, or fix documentation
- Suggest or add new features

## License

MIT. See [LICENSE](LICENSE).