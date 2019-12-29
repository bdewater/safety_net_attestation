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
      File.join(Dir.getwd, "lib", "safety_net_attestation", "certificates", "*.*")
    ).map do |path|
      file = File.binread(path)
      OpenSSL::X509::Certificate.new(file)
    end.freeze

    using FixedLengthSecureCompare

    attr_reader :json

    def initialize(jws_result)
      @jws_result = jws_result
    end

    def verify(nonce, timestamp_leeway: 60, trusted_certificates: GOOGLE_ROOT_CERTIFICATES)
      certificates = nil
      response, _ = JWT.decode(@jws_result, nil, true, algorithms: ["ES256", "RS256"]) do |headers|
        certificates = headers["x5c"].map do |encoded|
          OpenSSL::X509::Certificate.new(Base64.strict_decode64(encoded))
        end

        X5cKeyFinder.from(certificates, trusted_certificates)
      end

      verify_certificate_subject(certificates.first)
      verify_nonce(response, nonce)
      verify_timestamp(response, timestamp_leeway)

      @json = response
      @certificates = certificates
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

    def certificates
      raise NotVerifiedError unless json

      @certificates
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

    def verify_timestamp(response, leeway)
      now = Time.now.to_f
      response_time = response["timestampMs"] / 1000.0
      unless response_time.between?(now - leeway, now + leeway)
        raise TimestampError, "not within #{leeway}s leeway"
      end
    end
  end
end
