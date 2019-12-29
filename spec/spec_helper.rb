# frozen_string_literal: true

require "bundler/setup"
require "safety_net_attestation"

require "pry-byebug"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.order = :random
end

def generate_key
  OpenSSL::PKey::RSA.new(2048)
end

# rubocop:disable Naming/UncommunicativeMethodParamName
def generate_cert(dn, key, serial, issuer, not_before: nil, not_after: nil)
  cert = OpenSSL::X509::Certificate.new
  issuer = cert unless issuer
  cert.version = 2
  cert.serial = serial
  cert.subject = dn
  cert.issuer = issuer.subject
  cert.public_key = key
  now = Time.now
  cert.not_before = not_before || now - 3600
  cert.not_after = not_after || now + 3600
  cert
end

def issue_cert(dn, key, serial, extensions, issuer: nil, issuer_key: nil, not_before: nil, not_after: nil)
  cert = generate_cert(dn, key, serial, issuer, not_before: not_before, not_after: not_after)
  issuer = cert unless issuer
  issuer_key = key unless issuer_key
  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate = issuer
  extensions.each do |oid, value, critical|
    cert.add_extension(ef.create_extension(oid, value, critical))
  end
  cert.sign(issuer_key, "sha256")
  cert
end
# rubocop:enable Naming/UncommunicativeMethodParamName
