# SafetyNetAttestation

A Ruby gem to verify SafetyNet attestation statements from Google Play Services on your server.

This gem verifies that the statement:
- has a valid signature that is trusted using certificates from https://pki.goog/
- has the correct nonce
- has been generated recently (default allowed leeway from current time is 60 seconds)
- has a signing certificate with the correct subject

With a valid statement your application can then inspect the information contained about the device integrity, calling
app, and if applicable any integrity errors and potential solutions (see usage).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'safety_net_attestation'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install safety_net_attestation

## Usage

Request an attestation statement as described in the [Android developer documentation](https://developer.android.com/training/safetynet/attestation#request-attestation-process) and send the JWS response to your server application.

In your server application code, do the following:

```ruby
require "safety_net_attestation"

statement = begin 
  SafetyNetAttestation::Statement.new(jws_response).verify(nonce)
rescue SafetyNetAttestation::Error => e
  # Statement is not valid, you should abort
end

statement.json
# => {"apkPackageName": "com.package.name.of.requesting.app", "ctsProfileMatch": true, ... }

# snake cased convenience methods are available after #verify call succeeded, use these to make your specific checks: 
statement.cts_profile_match?
# => true
statement.basic_integrity?
# => true
statement.apk_package_name
# => "com.package.name.of.requesting.app"
statement.apk_certificate_digest_sha256
# => ["..."]
statement.error
# => nil
statement.advice
# => nil
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bin/rspec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/bdewater/safety_net_attestation. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

The gem and its authors are unaffiliated with Google.
