# frozen_string_literal: true

RSpec.describe SafetyNetAttestation::Statement do
  let(:root_key) { generate_key }
  let(:root_dn) { OpenSSL::X509::Name.new([["DC", "test"], ["CN", "Fake Google Root CA"]]) }
  let(:root_certificate) do
    extensions = [
      ["basicConstraints", "CA:TRUE", true],
      ["keyUsage", "keyCertSign,cRLSign", true]
    ]
    issue_cert(root_dn, root_key, 1, extensions)
  end

  let(:signing_key) { generate_key }
  let(:signing_dn) { OpenSSL::X509::Name.new([["CN", "attest.android.com"]]) }
  let(:signing_certificate) do
    extensions = [
      ["basicConstraints", "CA:FALSE", true],
      ["keyUsage", "digitalSignature,nonRepudiation", true]
    ]
    issue_cert(signing_dn, signing_key, 2, extensions, issuer: root_certificate, issuer_key: root_key)
  end

  let(:payload_timestamp) { Time.now.to_f - 5.0 }
  let(:payload) do
    {
      "timestampMs" => payload_timestamp * 1000.0,
      "nonce" => "R2Rra24fVm5xa2Mg",
      "apkPackageName" => "com.package.name.of.requesting.app",
      "apkCertificateDigestSha256" => [Digest::SHA256.base64digest("test")],
      "ctsProfileMatch" => true,
      "basicIntegrity" => true,
    }
  end
  let(:response) do
    JWT.encode(
      payload,
      signing_key,
      "RS256",
      x5c: [Base64.strict_encode64(signing_certificate.to_der)]
    )
  end

  let(:nonce) { "R2Rra24fVm5xa2Mg" }
  let(:leeway) { 60 }
  subject do
    described_class.new(response).verify(nonce, timestamp_leeway: leeway, trusted_certificates: [root_certificate])
  end

  it "returns itself and allows access to reader methods when everything is valid", :aggregate_failures do
    expect(subject).to be_a(described_class)

    expect(subject.cts_profile_match?).to be true
    expect(subject.basic_integrity?).to be true
    expect(subject.apk_package_name).to eq("com.package.name.of.requesting.app")
    expect(subject.apk_certificate_digest_sha256).to eq(["n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="])
    expect(subject.error).to be_nil
    expect(subject.advice).to be_nil
  end

  context "using reader methods before validation" do
    subject { described_class.new(response) }

    it("is expected to raise SafetyNetAttestation::NotVerifiedError", :aggregate_failures) do
      expect { subject.cts_profile_match? }.to raise_error(SafetyNetAttestation::NotVerifiedError)
      expect { subject.basic_integrity? }.to raise_error(SafetyNetAttestation::NotVerifiedError)
      expect { subject.apk_package_name }.to raise_error(SafetyNetAttestation::NotVerifiedError)
      expect { subject.apk_certificate_digest_sha256 }.to raise_error(SafetyNetAttestation::NotVerifiedError)
      expect { subject.error }.to raise_error(SafetyNetAttestation::NotVerifiedError)
      expect { subject.advice }.to raise_error(SafetyNetAttestation::NotVerifiedError)
    end
  end

  context "invalid JWT" do
    context "wrong signing certificate subject" do
      let(:signing_dn) { OpenSSL::X509::Name.new([["CN", "foobar.android.com"]]) }

      it do
        expect { subject }.to raise_error(SafetyNetAttestation::CertificateSubjectError)
      end
    end

    context "wrong nonce" do
      let(:nonce) { "foobar0123456789" }

      it do
        expect { subject }.to raise_error(SafetyNetAttestation::NonceMismatchError)
      end
    end

    context "timestamp outside of leeway" do
      let(:payload_timestamp) { Time.now.to_f - (2 * leeway) }

      it do
        expect { subject }.to raise_error(SafetyNetAttestation::TimestampError)
      end
    end
  end
end
