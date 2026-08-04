require "dnsruby"
require "ipaddr"

module MailResolver
  class Error < StandardError; end
  # NXDOMAIN, or NOERROR with no records of the type asked for.
  class NotFound < Error; end
  # NXDOMAIN: the name itself doesn't exist, not just records of that type.
  class NoSuchName < NotFound; end
  # No answer arrived in time.
  class Timeout < Error; end
  # SERVFAIL, REFUSED, or transport failure — distinct from NotFound's "nothing there".
  class ServerFailure < Error; end

  # DNS for mail. Built on dnsruby rather than Resolv, which collapses SERVFAIL/REFUSED into NXDOMAIN.
  class Resolver
    # One attempt per element; intervals double after the first, and the sum is the hard deadline.
    # Default: attempts at 0s, 5s, and 10s, over at 11s.
    TIMEOUTS = [ 5, 3, 3 ].freeze

    def initialize(timeouts: TIMEOUTS)
      @timeouts = timeouts
      @lock = Mutex.new
    end

    # TXT character-strings are joined into one value (RFC 7208 §3.3).
    def txt(name)
      records("TXT", name).map { |record| record.strings.join }
    end

    def a(name)
      records("A", name).map { |record| record.address.to_s }
    end

    # Dnsruby prints IPv6 in capitals; RFC 5952 §4.3 asks for lower case.
    def aaaa(name)
      records("AAAA", name).map { |record| record.address.to_s.downcase }
    end

    # A missing family contributes nothing; NXDOMAIN or nameserver failure still raises.
    def addresses(name)
      %w[ A AAAA ].flat_map { |type| family(type, name) }
    end

    # Equal preferences tie-break on the exchange name so callers always see the same order.
    def mx(name)
      records("MX", name).sort_by { |record| [ record.preference, record.exchange.to_s ] }
        .map { |record| record.exchange.to_s }
    end

    # Dnsruby puts the question name in `name` and the host in `domainname`.
    def ptr(address)
      records("PTR", IPAddr.new(address.to_s).reverse).map { |record| record.domainname.to_s }
    end

    def cname(name)
      records("CNAME", name).map { |record| record.domainname.to_s }
    end

    private
      def family(type, name)
        records(type, name).map { |record| record.address.to_s.downcase }
      rescue NoSuchName
        raise
      rescue NotFound
        []
      end

      # Filtered by type: a CNAME answer carries the alias beside the records it leads to.
      def records(type, name)
        answers = resolver.query(name.to_s, type).answer.select { |record| record.type == type }

        if answers.any?
          answers
        else
          raise NotFound, "no #{type} records for #{name}"
        end
      rescue Dnsruby::NXDomain
        raise NoSuchName, "no such name #{name}"
      rescue Dnsruby::ResolvTimeout
        # Descends from Timeout::Error, not Dnsruby::ResolvError.
        raise Timeout, "timed out resolving #{type} #{name}"
      # Connect/send failures arrive as bare IOError/SocketError/SystemCallError from dnsruby's queue.
      rescue Dnsruby::ResolvError, IOError, SocketError, SystemCallError => error
        raise ServerFailure, "couldn't resolve #{type} #{name}: #{reason(error)}"
      end

      def reason(error)
        if error.is_a?(Dnsruby::ResolvError)
          rcode(error)
        else
          without_backtrace(error.message)
        end
      end

      # Dnsruby rcode classes often carry no message, and `class.name` is nil on an anonymous class.
      def rcode(error)
        name = error.class.name&.split("::")&.last

        case
        when name.nil?                         then error.message
        when error.message == error.class.name then name
        else                                        "#{name}, #{error.message}"
        end
      end

      # Transport error messages carry dnsruby's own backtrace inline.
      def without_backtrace(message)
        message.sub(/\s*\[".*\z/m, "")
      end

      # Built once and shared so concurrent queries multiplex over one I/O thread.
      # Caching and DNSSEC are off — the former is process-global, the latter unused by callers.
      def resolver
        @lock.synchronize do
          @resolver ||= Dnsruby::Resolver.new(**options).tap do |dns|
            dns.dnssec = false
            dns.do_caching = false
            dns.query_timeout = @timeouts.sum
            dns.packet_timeout = @timeouts.first
            dns.retry_times = @timeouts.size
            # Dnsruby fires attempt n at 2^(n-1) times this; halving the first element lands the schedule.
            dns.retry_delay = @timeouts.first / 2.0
          end
        end
      rescue ArgumentError => error
        # Dnsruby raises this when no configured nameserver is usable.
        raise ServerFailure, "no usable nameserver: #{error.message}"
      end

      # Overridden by MailResolver::Testing::LocalNameserver to point at a loopback nameserver.
      def options
        {}
      end
  end
end
