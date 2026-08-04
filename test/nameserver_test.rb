require_relative "test_helper"
require "mailresolver/testing"
require "resolv"

# Pins what dnsruby actually raises per rcode — doubles can only assert that by decree.
class MailResolver::NameserverTest < MailResolver::TestCase
  LocalNameserver = MailResolver::Testing::LocalNameserver

  def test_a_servfail_from_a_real_nameserver_is_a_server_failure
    LocalNameserver.answering(:servfail) do |resolver|
      assert_raises MailResolver::ServerFailure do
        resolver.txt("example.com")
      end
    end
  end

  def test_a_refusal_from_a_real_nameserver_is_a_server_failure
    LocalNameserver.answering(:refused) do |resolver|
      assert_raises MailResolver::ServerFailure do
        resolver.txt("example.com")
      end
    end
  end

  def test_an_nxdomain_from_a_real_nameserver_is_a_no_such_name
    LocalNameserver.answering(:nxdomain) do |resolver|
      assert_raises MailResolver::NoSuchName do
        resolver.txt("example.com")
      end
    end
  end

  def test_an_empty_noerror_answer_from_a_real_nameserver_is_not_found
    LocalNameserver.answering(:noerror) do |resolver|
      assert_raises MailResolver::NotFound do
        resolver.txt("example.com")
      end
    end
  end

  def test_a_nameserver_that_never_replies_is_a_timeout
    LocalNameserver.answering(nil, timeouts: [ 0.2, 0.2 ]) do |resolver|
      assert_raises MailResolver::Timeout do
        resolver.txt("example.com")
      end
    end
  end

  def test_a_txt_answer_arrives_over_the_wire_with_its_character_strings_joined
    record = Resolv::DNS::Resource::IN::TXT.new("v=spf1 include:_spf.example.com ", "-all")

    LocalNameserver.answering(:noerror, records: [ record ]) do |resolver|
      assert_equal [ "v=spf1 include:_spf.example.com -all" ], resolver.txt("example.com")
    end
  end

  def test_an_alias_beside_the_answer_survives_the_wire_without_being_mistaken_for_it
    records = [
      Resolv::DNS::Resource::IN::CNAME.new(Resolv::DNS::Name.create("sel.esp.example.com.")),
      Resolv::DNS::Resource::IN::TXT.new("v=DKIM1; k=rsa; p=MIGf")
    ]

    LocalNameserver.answering(:noerror, records: records) do |resolver|
      assert_equal [ "v=DKIM1; k=rsa; p=MIGf" ], resolver.txt("sel._domainkey.example.com")
    end
  end
end
