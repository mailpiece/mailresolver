require_relative "lib/mailresolver/version"

Gem::Specification.new do |spec|
  spec.name = "mailresolver"
  spec.version = MailResolver::VERSION
  spec.platform = Gem::Platform::RUBY
  spec.required_ruby_version = ">= 3.4"
  spec.authors = [ "Simon Lev" ]

  spec.summary = "DNS resolution for mail, in Ruby."
  spec.description = "DNS resolution for mail, in Ruby. **mailresolver** is a small, injectable DNS client for mail libraries — TXT, A/AAAA, MX, PTR, and CNAME lookups."

  spec.homepage = "https://github.com/mailpiece/mailresolver"
  spec.license = "MIT"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir[
    "lib/**/*.rb",
    "CHANGELOG.md",
    "README.md",
    "LICENSE",
    "mailresolver.gemspec"
  ]
  spec.require_paths = [ "lib" ]

  # Resolv collapses SERVFAIL/REFUSED into empty answers; dnsruby does not.
  spec.add_dependency "dnsruby", "~> 1.74"
end
