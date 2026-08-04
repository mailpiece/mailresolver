require_relative "test_helper"

class MailResolver::ResolverTest < MailResolver::TestCase
  Reply = Struct.new(:answer)

  # Stands in for dnsruby so we test our mapping, not its ability to raise.
  class StubDns
    attr_reader :queries

    def initialize(answer)
      @answer = answer
      @queries = []
    end

    def query(name, type)
      @queries << [ name, type ]

      if @answer.is_a?(Exception)
        raise @answer
      else
        Reply.new(@answer)
      end
    end
  end

  class StubbedResolver < MailResolver::Resolver
    def initialize(answer)
      super()
      @answer = answer
    end

    def queries
      resolver.queries
    end

    private
      def resolver
        @stub ||= StubDns.new(@answer)
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
    resolver = answering([ record(:CNAME, domainname: "sel.esp.example.com") ])

    assert_equal [ "sel.esp.example.com" ], resolver.cname("sel._domainkey.example.com")
  end

  # Dnsruby returns the whole answer section; a CNAME beside a TXT has no `strings`.
  def test_an_alias_beside_the_answer_is_not_mistaken_for_it
    records = [
      record(:CNAME, domainname: "sel.esp.example.com"),
      record(:TXT, strings: [ "v=DKIM1; k=rsa; p=MIGf" ])
    ]

    assert_equal [ "v=DKIM1; k=rsa; p=MIGf" ], answering(records).txt("sel._domainkey.example.com")
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

    assert_includes error.message, "no TXT records for example.com"
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

    assert_equal "couldn't resolve TXT example.com: Network is unreachable", error.message
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

  # dnsruby multiplexes concurrent queries over one I/O thread only when the object is shared.
  def test_the_real_resolver_is_built_once
    resolver = MailResolver::Resolver.new

    assert_same resolver.send(:resolver), resolver.send(:resolver)
  end

  private
    def answering(answer)
      StubbedResolver.new(answer)
    end

    def silencing_warnings
      original_verbose = $VERBOSE
      $VERBOSE = nil
      yield
    ensure
      $VERBOSE = original_verbose
    end

    def record(type, **attributes)
      Struct.new(:type, *attributes.keys, keyword_init: true).new(type: type.to_s, **attributes)
    end
end
