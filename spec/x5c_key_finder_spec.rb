# frozen_string_literal: true

require "spec_helper"
require "safety_net_attestation/x5c_key_finder"

RSpec.describe SafetyNetAttestation::X5cKeyFinder do
  let(:root_key) { generate_key }
  let(:root_dn) { OpenSSL::X509::Name.parse("/DC=org/DC=fake-ca/CN=Fake CA") }
  let(:root_certificate) do
    extensions = [
      ["basicConstraints", "CA:TRUE", true],
      ["keyUsage", "keyCertSign,cRLSign", true]
    ]
    issue_cert(root_dn, root_key, 1, extensions)
  end

  let(:leaf_key) { generate_key }
  let(:leaf_dn) { OpenSSL::X509::Name.parse("/DC=org/DC=fake/CN=Fake") }
  let(:leaf_serial) { 2 }
  let(:leaf_not_after) { Time.now + 3600 }
  let(:leaf_signing_key) { root_key }
  let(:leaf_certificate) do
    extensions = [
      ["basicConstraints", "CA:FALSE", true],
      ["keyUsage", "digitalSignature,nonRepudiation", true]
    ]
    issue_cert(leaf_dn, leaf_key, leaf_serial, extensions, issuer: root_certificate, issuer_key: leaf_signing_key,
                                                           not_after: leaf_not_after)
  end

  let(:x5c_certificates) { [leaf_certificate] }
  subject(:keyfinder) { described_class.from(x5c_certificates, [root_certificate]) }

  it "returns the public key from a certificate that is signed by trusted roots" do
    expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
    expect(keyfinder.to_pem).to eq(leaf_certificate.public_key.to_pem)
  end

  context "certificate" do
    context "expired" do
      let(:leaf_not_after) { Time.now - 3600 }

      it "raises an error" do
        error = "Certificate verification failed: certificate has expired. Certificate subject: " \
          "/DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(SafetyNetAttestation::SignatureError, error)
      end
    end

    context "signature could not be verified with the given trusted roots" do
      let(:leaf_signing_key) { generate_key }

      it "raises an error" do
        error = "Certificate verification failed: certificate signature failure. Certificate subject: " \
          "/DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(SafetyNetAttestation::SignatureError, error)
      end
    end

    context "could not be chained to a trusted root certificate" do
      subject(:keyfinder) { described_class.from(x5c_certificates, []) }

      it "raises an error" do
        error = "Certificate verification failed: unable to get local issuer certificate. Certificate subject: " \
          "/DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(SafetyNetAttestation::SignatureError, error)
      end
    end
  end
end
