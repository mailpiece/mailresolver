require "socket"
require "resolv"

module MailResolver
  # Doubles for tests that need DNS to misbehave. Require from your test helper:
  #
  #   require "mailresolver/testing"
  module Testing
    # A zone in a hash: missing names raise NoSuchName, missing types raise NotFound,
    # and :timeout/:servfail/:nxdomain stand in for misbehavior. PTR is keyed by address.
    #
    #   FakeResolver.new("example.com" => { txt: [ "v=spf1 -all" ], mx: :servfail })
    class FakeResolver
      attr_reader :queries

      def initialize(zone = {})
        @zone = zone.transform_keys { |name| normalized(name) }
        @queries = []
      end

      def txt(name)
        lookup(name, :txt)
      end

      def a(name)
        lookup(name, :a)
      end

      def aaaa(name)
        lookup(name, :aaaa)
      end

      # A missing family contributes nothing; NXDOMAIN or nameserver failure still raises.
      def addresses(name)
        %i[ a aaaa ].flat_map { |type| family(type, name) }
      end

      def mx(name)
        lookup(name, :mx)
      end

      def ptr(address)
        lookup(address, :ptr)
      end

      def cname(name)
        lookup(name, :cname)
      end

      private
        def family(type, name)
          lookup(name, type)
        rescue NoSuchName
          raise
        rescue NotFound
          []
        end

        def lookup(name, type)
          key = normalized(name)
          @queries << [ key, type ]

          case records = @zone.dig(key, type)
          when :timeout  then raise Timeout, "timed out resolving #{type.upcase} #{key}"
          when :servfail then raise ServerFailure, "server failure resolving #{type.upcase} #{key}"
          when :nxdomain then raise NoSuchName, "no such name #{key}"
          when nil, []   then raise absence(key, type)
          else records
          end
        end

        # A name the zone never mentions doesn't exist; one there without this type does.
        def absence(key, type)
          if @zone.key?(key)
            NotFound.new("no #{type.upcase} records for #{key}")
          else
            NoSuchName.new("no such name #{key}")
          end
        end

        def normalized(name)
          name.to_s.downcase.chomp(".")
        end
    end

    # A loopback nameserver for one rcode (records for :noerror, [name, record]
    # for an alias, nil for a timeout), with replies encoded via Resolv.
    #
    #   LocalNameserver.answering(:servfail) do |resolver|
    #     assert_raises(MailResolver::ServerFailure) { resolver.txt("example.com") }
    #   end
    class LocalNameserver
      RCODES = { noerror: 0, servfail: 2, nxdomain: 3, refused: 5 }.freeze
      TIMEOUTS = [ 0.5 ].freeze

      def self.answering(rcode, records: [], timeouts: TIMEOUTS)
        nameserver = new(rcode, records: records)
        yield nameserver.resolver(timeouts: timeouts)
      ensure
        nameserver&.close
      end

      def initialize(rcode, records: [])
        @rcode, @records = rcode, records
        @socket = UDPSocket.new
        @socket.bind("127.0.0.1", 0)
        @thread = Thread.new { serve }
      end

      def port
        @socket.addr[1]
      end

      def resolver(timeouts: TIMEOUTS)
        LocalResolver.new(port, timeouts: timeouts)
      end

      def close
        @thread.kill
        @socket.close
      end

      # Overrides options so configuring a nameserver stays off the public API.
      class LocalResolver < Resolver
        def initialize(port, **options)
          super(**options)
          @port = port
        end

        private
          def options
            { nameserver: "127.0.0.1", port: @port }
          end
      end

      private
        def serve
          loop do
            message, sender = @socket.recvfrom(4096)
            @socket.send(reply_to(message).encode, 0, sender[3], sender[1]) if @rcode
          end
        rescue IOError, Errno::EBADF
          nil
        end

        def reply_to(message)
          query = Resolv::DNS::Message.decode(message)
          reply = Resolv::DNS::Message.new(query.id)
          reply.qr = 1
          reply.rd = query.rd
          reply.ra = 1
          reply.rcode = RCODES.fetch(@rcode)

          query.each_question do |name, typeclass|
            reply.add_question(name, typeclass)

            @records.each do |record|
              if record.is_a?(Array)
                reply.add_answer(Resolv::DNS::Name.create(record.first), 60, record.last)
              else
                reply.add_answer(name, 60, record)
              end
            end
          end

          reply
        end
    end
  end
end
