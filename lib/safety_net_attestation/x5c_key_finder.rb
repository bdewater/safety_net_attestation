# frozen_string_literal: true

require "base64"
require_relative "errors"

module SafetyNetAttestation
  class SignatureError < Error; end

  class X5cKeyFinder
    def self.from(x5c_certificates, trusted_certificates, time: Time.now)
      store = OpenSSL::X509::Store.new
      trusted_certificates.each { |certificate| store.add_cert(certificate) }

      signing_certificate, *certificate_chain = x5c_certificates
      store_context = OpenSSL::X509::StoreContext.new(store, signing_certificate, certificate_chain)
      store_context.time = time

      if store_context.verify
        store_context.chain
      else
        error = "Certificate verification failed: #{store_context.error_string}."
        error = "#{error} Certificate subject: #{store_context.current_cert.subject}." if store_context.current_cert

        raise SignatureError, error
      end
    end
  end
end
