require_relative "test_helper"
require "mailresolver/testing"

# FakeResolver stands in for Resolver elsewhere, so both must answer absence the same way.
class MailResolver::TestingTest < MailResolver::TestCase
  ZONE = {
    "example.com" => { txt: [ "v=spf1 -all" ], a: [ "192.0.2.1" ], aaaa: [ "2001:db8::1" ] },
    "ipv4.example.com" => { a: [ "192.0.2.2" ] },
    "quiet.example.com" => { txt: [] },
    "broken.example.com" => { txt: :servfail, a: :timeout, mx: :nxdomain },
    "192.0.2.1" => { ptr: [ "mail.example.com" ] }
  }.freeze

  def test_a_name_the_zone_publishes_answers_with_its_records
    assert_equal [ "v=spf1 -all" ], resolver.txt("example.com")
    assert_equal [ "mail.example.com" ], resolver.ptr("192.0.2.1")
  end

  def test_names_are_matched_without_regard_to_case_or_a_trailing_root
    assert_equal [ "v=spf1 -all" ], resolver.txt("Example.COM.")
  end

  def test_a_name_the_zone_never_mentions_does_not_exist
    assert_raises MailResolver::NoSuchName do
      resolver.txt("absent.example.com")
    end
  end

  # NoSuchName descends from NotFound so callers can catch both.
  def test_a_name_without_records_of_that_type_is_absence_short_of_nonexistence
    error = assert_raises(MailResolver::NotFound) { resolver.mx("example.com") }

    refute_kind_of MailResolver::NoSuchName, error
  end

  def test_an_empty_record_list_reads_as_no_records_of_that_type
    assert_raises MailResolver::NotFound do
      resolver.txt("quiet.example.com")
    end
  end

  def test_the_sentinels_raise_the_failure_they_name
    assert_raises(MailResolver::ServerFailure) { resolver.txt("broken.example.com") }
    assert_raises(MailResolver::Timeout) { resolver.a("broken.example.com") }
    assert_raises(MailResolver::NoSuchName) { resolver.mx("broken.example.com") }
  end

  def test_addresses_merges_both_families
    assert_equal [ "192.0.2.1", "2001:db8::1" ], resolver.addresses("example.com")
  end

  def test_addresses_treats_a_family_the_name_does_not_publish_as_nothing
    assert_equal [ "192.0.2.2" ], resolver.addresses("ipv4.example.com")
  end

  def test_addresses_still_raises_for_a_name_that_does_not_exist
    assert_raises MailResolver::NoSuchName do
      resolver.addresses("absent.example.com")
    end
  end

  def test_every_lookup_is_recorded_for_callers_counting_them
    fake = resolver
    fake.txt("example.com")
    fake.mx("example.com") rescue nil

    assert_equal [ [ "example.com", :txt ], [ "example.com", :mx ] ], fake.queries
  end

  private
    def resolver
      MailResolver::Testing::FakeResolver.new(ZONE)
    end
end
