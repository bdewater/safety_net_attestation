# frozen_string_literal: true

module SafetyNetAttestation
  class Error < StandardError; end
  class NotVerifiedError < Error; end
  class NonceMismatchError < Error; end
  class TimestampError < Error; end
  class CertificateSubjectError < Error; end
end
