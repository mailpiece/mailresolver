require_relative "test_helper"

class MailResolver::ResolverTest < MailResolver::TestCase
  Reply = Struct.new(:answer, :rcode, :header)
  Header = Struct.new(:tc)

  # Stands in for dnsruby so we test our mapping, not its ability to raise.
  class StubDns
    attr_reader :queries

    def initialize(answer, rcode: Dnsruby::RCode::NOERROR, truncated: false)
      @answer = answer
      @rcode, @truncated = rcode, truncated
      @queries = []
    end

    def send_async(message, replies, id)
      question = message.question.first
      @queries << [ question.qname.to_s, question.qtype.to_s ]

      if @answer.is_a?(Exception)
        replies.push([ id, nil, @answer ])
      else
        replies.push([ id, Reply.new(@answer, Dnsruby::RCode.new(@rcode), Header.new(@truncated)), nil ])
      end
    end
  end

  # Dnsruby whose I/O thread never answers, as after a fork or behind a stalled TCP connect.
  class SilentDns < Dnsruby::Resolver
    def send_async(*)
    end
  end

  class StubbedResolver < MailResolver::Resolver
    def initialize(answer, **reply)
      super()
      @answer, @reply = answer, reply
    end

    def queries
      resolver.queries
    end

    private
      def resolver
        @stub ||= StubDns.new(@answer, **@reply)
      end
  end

  # Connect/send failures arrive as bare errors on dnsruby's queue, not Dnsruby errors.
  CONNECT_FAILURE = "dnsruby can't connect to 2001:db8::1:53 from :::55672, use_tcp=false, " \
    "exception = Errno::ENETUNREACH, Network is unreachable - connect(2) for \"2001:db8::1\" port 53 " \
    "[\"dnsruby-1.74.0/lib/dnsruby/packet_sender.rb:491:in 'UDPSocket#connect'\", " \
    "\"dnsruby-1.74.0/lib/dnsruby/resolver.rb:200:in 'Dnsruby::Resolver#query'\"]"

  def test_txt_joins_character_strings_of_one_record
    resolver = answering([ record(:TXT, strings: [ "v=spf1 include:_spf.example.com ", "-all" ]) ])

    assert_equal [ "v=spf1 include:_spf.example.com -all" ], resolver.txt("example.com")
  end

  def test_txt_answers_one_value_per_record
    resolver = answering([
      record(:TXT, strings: [ "v=spf1 -all" ]),
      record(:TXT, strings: [ "v=DKIM1; k=rsa; p=MIGf" ])
    ])

    assert_equal [ "v=spf1 -all", "v=DKIM1; k=rsa; p=MIGf" ], resolver.txt("example.com")
  end

  def test_a_returns_addresses
    resolver = answering([ record(:A, address: "203.0.113.10") ])

    assert_equal [ "203.0.113.10" ], resolver.a("example.com")
  end

  # RFC 5952 §4.3; Dnsruby prints IPv6 in capitals.
  def test_aaaa_downcases_addresses
    resolver = answering([ record(:AAAA, address: "2001:DB8::1") ])

    assert_equal [ "2001:db8::1" ], resolver.aaaa("example.com")
  end

  def test_mx_arrives_sorted_by_preference
    resolver = answering([
      record(:MX, preference: 30, exchange: "c.example.com"),
      record(:MX, preference: 10, exchange: "a.example.com"),
      record(:MX, preference: 20, exchange: "b.example.com")
    ])

    assert_equal %w[a.example.com b.example.com c.example.com], resolver.mx("example.com")
  end

  def test_equal_mx_preferences_arrive_in_the_same_order_every_time
    resolver = answering([
      record(:MX, preference: 10, exchange: "b.example.com"),
      record(:MX, preference: 10, exchange: "a.example.com")
    ])

    assert_equal %w[a.example.com b.example.com], resolver.mx("example.com")
  end

  # Dnsruby puts the question in `name` and the host in `domainname`.
  def test_ptr_reverses_the_address_and_answers_with_the_host
    resolver = answering([ record(:PTR, name: "10.113.0.203.in-addr.arpa", domainname: "mail.example.com") ])

    assert_equal [ "mail.example.com" ], resolver.ptr("203.0.113.10")
    assert_equal [ [ "10.113.0.203.in-addr.arpa", "PTR" ] ], resolver.queries
  end

  def test_ptr_reverses_an_ipv6_address_under_ip6_arpa
    reversed = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    resolver = answering([ record(:PTR, name: reversed, domainname: "mail.example.com") ])

    assert_equal [ "mail.example.com" ], resolver.ptr("2001:db8::1")
    assert_equal [ [ reversed, "PTR" ] ], resolver.queries
  end

  def test_ptr_of_a_malformed_address_is_an_argument_error
    assert_raises ArgumentError do
      answering([]).ptr("not an ip")
    end
  end

  def test_cname_answers_with_the_alias_target
    resolver = answering([ record(:CNAME, name: "sel._domainkey.example.com", domainname: "sel.esp.example.com") ])

    assert_equal [ "sel.esp.example.com" ], resolver.cname("sel._domainkey.example.com")
  end

  def test_ns_answers_with_the_nameservers
    resolver = answering([ record(:NS, domainname: "ns1.example.net"), record(:NS, domainname: "ns2.example.net") ])

    assert_equal [ "ns1.example.net", "ns2.example.net" ], resolver.ns("example.com")
  end

  # Dnsruby returns the whole answer section; a CNAME beside a TXT has no `strings`.
  def test_an_alias_beside_the_answer_is_not_mistaken_for_it
    records = [
      record(:CNAME, name: "sel._domainkey.example.com", domainname: "sel.esp.example.com"),
      record(:TXT, name: "sel.esp.example.com", strings: [ "v=DKIM1; k=rsa; p=MIGf" ])
    ]

    assert_equal [ "v=DKIM1; k=rsa; p=MIGf" ], answering(records).txt("sel._domainkey.example.com")
  end

  def test_records_another_name_owns_are_not_the_answer
    records = [ record(:TXT, name: "_dmarc.victim.example", strings: [ "v=DMARC1; p=none" ]) ]

    assert_raises(MailResolver::NotFound) { answering(records).txt("example.com") }
    assert_raises(MailResolver::NotFound) { answering([ record(:A, name: "other.example", address: "192.0.2.1") ]).a("example.com") }
  end

  def test_owners_match_without_regard_to_case
    resolver = answering([ record(:A, name: "Example.COM", address: "192.0.2.1") ])

    assert_equal [ "192.0.2.1" ], resolver.a("example.com")
  end

  def test_an_alias_chain_is_followed_to_the_records_it_leads_to
    records = [
      record(:A, name: "stray.example", address: "192.0.2.9"),
      record(:CNAME, name: "b.example", domainname: "c.example"),
      record(:A, name: "c.example", address: "192.0.2.1"),
      record(:CNAME, name: "example.com", domainname: "b.example")
    ]

    assert_equal [ "192.0.2.1" ], answering(records).a("example.com")
  end

  def test_an_address_is_answered_for_the_reverse_name_dnsruby_asks
    resolver = answering([ record(:TXT, name: "1.2.0.192.in-addr.arpa", strings: [ "v=spf1 -all" ]) ])

    assert_equal [ "v=spf1 -all" ], resolver.txt("192.0.2.1")
  end

  def test_an_alias_loop_is_not_found
    records = [ record(:CNAME, domainname: "b.example"), record(:CNAME, name: "b.example", domainname: "example.com") ]

    assert_raises(MailResolver::NotFound) { answering(records).txt("example.com") }
  end

  def test_an_alias_chain_ends_after_sixteen_hops
    chain = ->(hops) do
      names = [ "example.com", *(1..hops).map { |hop| "h#{hop}.example" } ]
      names.each_cons(2).map { |from, to| record(:CNAME, name: from, domainname: to) } +
        [ record(:A, name: names.last, address: "192.0.2.1") ]
    end

    assert_equal [ "192.0.2.1" ], answering(chain.(16)).a("example.com")
    assert_raises(MailResolver::NotFound) { answering(chain.(17)).a("example.com") }
  end

  def test_cname_answers_with_the_first_alias_only
    records = [
      record(:CNAME, domainname: "b.example"),
      record(:CNAME, name: "b.example", domainname: "c.example")
    ]

    assert_equal [ "b.example" ], answering(records).cname("example.com")
  end

  def test_addresses_merges_a_and_aaaa
    resolver = answering([ record(:A, address: "203.0.113.10"), record(:AAAA, address: "2001:DB8::1") ])

    assert_equal [ "203.0.113.10", "2001:db8::1" ], resolver.addresses("example.com")
  end

  def test_addresses_answers_empty_when_neither_family_is_published
    assert_equal [], answering([]).addresses("example.com")
  end

  def test_addresses_still_raises_when_the_name_does_not_exist
    assert_raises MailResolver::NoSuchName do
      answering(Dnsruby::NXDomain.new("example.com")).addresses("example.com")
    end
  end

  def test_addresses_still_raises_on_a_server_failure
    assert_raises MailResolver::ServerFailure do
      answering(Dnsruby::ServFail.new("example.com")).addresses("example.com")
    end
  end

  def test_an_nxdomain_is_a_no_such_name_which_is_not_found
    error = assert_raises MailResolver::NoSuchName do
      answering(Dnsruby::NXDomain.new("example.com")).txt("example.com")
    end

    assert_kind_of MailResolver::NotFound, error
  end

  def test_no_records_of_the_type_asked_for_is_not_found
    assert_raises MailResolver::NotFound do
      answering([]).txt("example.com")
    end
  end

  def test_not_found_names_the_record_type
    error = assert_raises MailResolver::NotFound do
      answering([]).txt("example.com")
    end

    assert_includes error.message, "no TXT records for \"example.com\""
  end

  def test_a_name_reaches_an_error_message_quoted_with_its_control_characters_escaped
    error = assert_raises MailResolver::NotFound do
      answering([]).txt("example.com\r\nX-Injected: 1\0")
    end

    assert_includes error.message, "\"example.com\\r\\nX-Injected: 1\\u0000\""
    refute_match(/[\r\n\0]/, error.message)
  end

  def test_a_servfail_is_a_server_failure
    assert_raises MailResolver::ServerFailure do
      answering(Dnsruby::ServFail.new("example.com")).txt("example.com")
    end
  end

  def test_a_refused_query_is_a_server_failure
    assert_raises MailResolver::ServerFailure do
      answering(Dnsruby::Refused.new("example.com")).txt("example.com")
    end
  end

  # Dnsruby raises only for the rcodes it knows, and hands the rest back as answers.
  def test_an_rcode_dnsruby_does_not_know_is_a_server_failure
    error = assert_raises MailResolver::ServerFailure do
      answering([ record(:TXT, strings: [ "v=spf1 +all" ]) ], rcode: 11).txt("example.com")
    end

    assert_includes error.message, "rcode 11"
  end

  # Go's resolver answers these with errNoSuchHost, without asking.
  def test_a_name_dns_cannot_carry_does_not_exist_and_is_never_asked_for
    [ "", ".", "a..example.com", "#{"a" * 64}.example.com", "#{"a" * 63}.#{"b" * 63}.#{"c" * 63}.#{"d" * 62}",
      "a\\.b.example.com", "a\\046b.example.com" ].each do |name|
      resolver = answering([ record(:TXT, strings: [ "v=spf1 -all" ]) ])

      assert_raises(MailResolver::NoSuchName, name) { resolver.txt(name) }
      assert_empty resolver.queries, name
    end
  end

  def test_a_name_at_the_length_limit_is_asked_for_with_or_without_its_trailing_dot
    name = "#{"a" * 63}.#{"b" * 63}.#{"c" * 63}.#{"d" * 61}"

    [ name, "#{name}." ].each do |asked|
      assert_equal [ "v=spf1 -all" ], answering([ record(:TXT, name: name, strings: [ "v=spf1 -all" ]) ]).txt(asked)
    end
  end

  def test_no_name_is_an_argument_error
    assert_raises ArgumentError do
      answering([]).txt(nil)
    end
  end

  # Dnsruby retries a truncated reply over TCP, but accepts one truncated there too.
  def test_a_truncated_reply_is_a_server_failure
    error = assert_raises MailResolver::ServerFailure do
      answering([ record(:TXT, strings: [ "v=spf1 -all" ]) ], truncated: true).txt("example.com")
    end

    assert_includes error.message, "truncated"
  end

  # Unrecognised errors must not fall through to NotFound.
  def test_an_unrecognised_resolv_error_is_a_server_failure_not_a_missing_record
    assert_raises MailResolver::ServerFailure do
      answering(Dnsruby::ResolvError.new("some wording a later dnsruby invents")).txt("example.com")
    end
  end

  # ResolvTimeout descends from Timeout::Error, not Dnsruby::ResolvError.
  def test_a_timeout_is_a_timeout_not_a_missing_record
    error = assert_raises MailResolver::Timeout do
      answering(Dnsruby::ResolvTimeout.new("query timed out")).txt("example.com")
    end

    assert_includes error.message, "example.com"
  end

  def test_an_ioerror_does_not_escape_and_is_a_server_failure
    assert_raises MailResolver::ServerFailure do
      answering(IOError.new(CONNECT_FAILURE)).txt("example.com")
    end
  end

  def test_a_socket_error_does_not_escape_and_is_a_server_failure
    assert_raises MailResolver::ServerFailure do
      answering(SocketError.new("getaddrinfo: Name or service not known")).txt("example.com")
    end
  end

  def test_a_system_call_error_does_not_escape_and_is_a_server_failure
    assert_raises MailResolver::ServerFailure do
      answering(Errno::ENETUNREACH.new).txt("example.com")
    end
  end

  def test_a_connect_failure_reads_as_the_address_and_the_errno_without_a_backtrace
    error = assert_raises MailResolver::ServerFailure do
      answering(IOError.new(CONNECT_FAILURE)).txt("example.com")
    end

    assert_includes error.message, "example.com"
    assert_includes error.message, "2001:db8::1:53"
    assert_includes error.message, "Network is unreachable"
    refute_includes error.message, "packet_sender.rb"
    refute_includes error.message, "IOError"
  end

  # Bare rcode classes would otherwise surface as "Dnsruby::ServFail".
  def test_a_bare_rcode_error_is_named_by_its_rcode_not_its_class
    error = assert_raises MailResolver::ServerFailure do
      answering(Dnsruby::ServFail.new("example.com")).txt("example.com")
    end

    assert_includes error.message, "ServFail"
    refute_includes error.message, "Dnsruby::ServFail"
  end

  def test_an_errno_keeps_its_own_wording
    error = assert_raises MailResolver::ServerFailure do
      answering(Errno::ENETUNREACH.new).txt("example.com")
    end

    assert_equal "couldn't resolve TXT \"example.com\": Network is unreachable", error.message
  end

  def test_no_usable_nameserver_is_a_server_failure_not_a_raw_argument_error
    original = Dnsruby::Resolver.method(:new)

    silencing_warnings do
      Dnsruby::Resolver.define_singleton_method(:new) { |*| raise ArgumentError, "no nameservers found" }
    end

    error = assert_raises MailResolver::ServerFailure do
      MailResolver::Resolver.new.txt("example.com")
    end

    assert_includes error.message, "no usable nameserver"
  ensure
    silencing_warnings { Dnsruby::Resolver.define_singleton_method(:new, original) }
  end

  def test_the_real_resolver_does_not_validate_dnssec
    refute MailResolver::Resolver.new.send(:resolver).dnssec
  end

  def test_the_real_resolver_does_not_cache
    refute MailResolver::Resolver.new.send(:resolver).do_caching
  end

  # Dnsruby advertises its udp_size in each query's OPT record.
  def test_the_real_resolver_advertises_a_1232_byte_edns_buffer
    assert_equal 1232, MailResolver::Resolver.new.send(:resolver).udp_size
  end

  # Dnsruby fires attempt n at 2^(n-1) times retry_delay; 2.5 lands [5, 3, 3] at 0s/5s/10s.
  def test_the_real_resolver_retries_on_the_documented_schedule
    resolver = MailResolver::Resolver.new.send(:resolver)

    assert_equal 3, resolver.retry_times
    assert_equal 5, resolver.packet_timeout
    assert_equal 11, resolver.query_timeout
    assert_equal 2.5, resolver.retry_delay
  end

  # Elements after the first only ever feed the summed deadline, never the doubling schedule itself.
  def test_only_the_first_timeout_and_the_count_control_the_retry_schedule
    resolver = MailResolver::Resolver.new(timeouts: [ 2, 10, 10 ]).send(:resolver)

    assert_equal 3, resolver.retry_times
    assert_equal 2, resolver.packet_timeout
    assert_equal 22, resolver.query_timeout
    assert_equal 1.0, resolver.retry_delay
  end

  # A deadline shorter than dnsruby's default retry pacing must still retry.
  def test_timeouts_are_configurable
    resolver = MailResolver::Resolver.new(timeouts: [ 1, 1 ]).send(:resolver)

    assert_equal 2, resolver.retry_times
    assert_equal 1, resolver.packet_timeout
    assert_equal 2, resolver.query_timeout
    assert_equal 0.5, resolver.retry_delay
  end

  def test_nameservers_reach_dnsruby
    resolver = MailResolver::Resolver.new(nameservers: [ "192.0.2.53", "2001:db8::53" ]).send(:resolver)

    assert_equal [ "192.0.2.53", "2001:db8::53" ], resolver.config.nameserver
  end

  def test_one_nameserver_may_be_given_on_its_own
    resolver = MailResolver::Resolver.new(nameservers: "192.0.2.53").send(:resolver)

    assert_equal [ "192.0.2.53" ], resolver.config.nameserver
  end

  def test_without_nameservers_the_system_resolver_answers
    assert_equal Dnsruby::Resolver.new.config.nameserver, MailResolver::Resolver.new.send(:resolver).config.nameserver
  end

  # Dnsruby would look a name up over the network, then drop it if it found nothing.
  def test_a_nameserver_that_is_not_an_address_is_a_server_failure
    error = assert_raises MailResolver::ServerFailure do
      MailResolver::Resolver.new(nameservers: [ "192.0.2.53", "not an address" ]).txt("example.com")
    end

    assert_includes error.message, "no usable nameserver"
  end

  def test_a_query_dnsruby_never_answers_times_out_at_the_deadline
    resolver = MailResolver::Resolver.new(timeouts: [ 0.2 ])
    resolver.instance_variable_set(:@resolver, SilentDns.new(nameserver: "127.0.0.1"))

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_raises(MailResolver::Timeout) { resolver.txt("example.com") }
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1
  end

  def test_timeouts_that_are_not_positive_numbers_are_an_argument_error
    [ [], [ 0, 1 ], [ -1 ], [ "5" ], [ Float::INFINITY ], [ Float::NAN ], 5, nil ].each do |timeouts|
      assert_raises(ArgumentError, timeouts.inspect) { MailResolver::Resolver.new(timeouts: timeouts) }
    end
  end

  # Dnsruby would be left with no nameserver, and every query would time out.
  def test_no_nameservers_is_an_argument_error
    assert_raises ArgumentError do
      MailResolver::Resolver.new(nameservers: [])
    end
  end

  def test_nameservers_may_be_given_as_ip_addresses
    resolver = MailResolver::Resolver.new(nameservers: [ IPAddr.new("192.0.2.53"), IPAddr.new("2001:db8::53") ])

    assert_equal [ "192.0.2.53", "2001:db8::53" ], resolver.send(:resolver).config.nameserver
  end

  # IPAddr would mask 192.0.2.0/0 down to 0.0.0.0.
  def test_a_nameserver_given_as_a_range_is_a_server_failure
    [ "192.0.2.53/0", "192.0.2.0/24", IPAddr.new("2001:db8::/32") ].each do |range|
      error = assert_raises MailResolver::ServerFailure, range.inspect do
        MailResolver::Resolver.new(nameservers: [ range ]).txt("example.com")
      end

      assert_includes error.message, "is a range"
    end
  end

  # dnsruby multiplexes concurrent queries over one I/O thread only when the object is shared.
  def test_the_real_resolver_is_built_once
    resolver = MailResolver::Resolver.new

    assert_same resolver.send(:resolver), resolver.send(:resolver)
  end

  private
    def answering(answer, **reply)
      StubbedResolver.new(answer, **reply)
    end

    def silencing_warnings
      original_verbose = $VERBOSE
      $VERBOSE = nil
      yield
    ensure
      $VERBOSE = original_verbose
    end

    # Owned by example.com unless named; names are absolute, as they arrive off the wire.
    def record(type, name: "example.com", **attributes)
      attributes[:domainname] &&= absolute(attributes[:domainname])

      Struct.new(:type, :name, *attributes.keys, keyword_init: true)
        .new(type: type.to_s, name: absolute(name), **attributes)
    end

    def absolute(name)
      Dnsruby::Name.create("#{name}.")
    end
end
