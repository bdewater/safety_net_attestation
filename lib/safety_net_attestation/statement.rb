# frozen_string_literal: true

require "jwt"
require "openssl"
require "time"
require_relative "errors"
require_relative "fixed_length_secure_compare"
require_relative "x5c_key_finder"

module SafetyNetAttestation
  class Statement
    GOOGLE_ROOT_CERTIFICATES = Dir.glob(
      File.join(SafetyNetAttestation::GEM_ROOT, "safety_net_attestation", "certificates", "*.*")
    ).map do |path|
      file = File.binread(path)
      OpenSSL::X509::Certificate.new(file)
    end.freeze

    using FixedLengthSecureCompare

    attr_reader :json

    def initialize(jws_result)
      @jws_result = jws_result
    end

    def verify(nonce, timestamp_leeway: 60, trusted_certificates: GOOGLE_ROOT_CERTIFICATES, time: Time.now)
      certificate_chain = nil
      response, _ = JWT.decode(@jws_result, nil, true, algorithms: ["ES256", "RS256"]) do |headers|
        x5c_certificates = headers["x5c"].map do |encoded|
          OpenSSL::X509::Certificate.new(Base64.strict_decode64(encoded))
        end

        certificate_chain = X5cKeyFinder.from(x5c_certificates, trusted_certificates, time: time)
        certificate_chain.first.public_key
      end

      verify_certificate_subject(certificate_chain.first)
      verify_nonce(response, nonce)
      verify_timestamp(response, timestamp_leeway, time)

      @json = response
      @certificate_chain = certificate_chain
      self
    end

    def cts_profile_match?
      raise NotVerifiedError unless json

      json["ctsProfileMatch"]
    end

    def basic_integrity?
      raise NotVerifiedError unless json

      json["basicIntegrity"]
    end

    def apk_package_name
      raise NotVerifiedError unless json

      json["apkPackageName"]
    end

    def apk_certificate_digest_sha256
      raise NotVerifiedError unless json

      json["apkCertificateDigestSha256"]
    end

    def error
      raise NotVerifiedError unless json

      json["error"]
    end

    def advice
      raise NotVerifiedError unless json

      json["advice"]&.split(",")
    end

    def certificate_chain
      raise NotVerifiedError unless json

      @certificate_chain
    end

    private

    def verify_certificate_subject(certificate)
      common_name = certificate.subject.to_a.assoc("CN")

      unless common_name[1] == "attest.android.com"
        raise CertificateSubjectError
      end
    end

    def verify_nonce(response, nonce)
      unless OpenSSL.fixed_length_secure_compare(nonce, response["nonce"])
        raise NonceMismatchError
      end
    end

    def verify_timestamp(response, leeway, time)
      now = time.to_f
      response_time = response["timestampMs"] / 1000.0
      unless response_time.between?(now - leeway, now + leeway)
        raise TimestampError, "not within #{leeway}s leeway"
      end
    end
  end
end
