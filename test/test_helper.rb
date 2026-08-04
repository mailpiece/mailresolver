$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "mailresolver"

module MailResolver
  class TestCase < Minitest::Test
  end
end
