source "https://rubygems.org"

# Rails and core dependencies
gem "rails", "~> 8.0.0.beta1"
gem "sqlite3", ">= 2.1"
gem "puma", ">= 5.0"

# Performance and caching
gem "bootsnap", require: false
gem "solid_cache"
gem "solid_queue"
gem "solid_cable"
gem "thruster", require: false

gem "jbuilder"
gem "bcrypt"
gem "jwt"
gem "rack-cors"
gem "rack-attack"

# Deployment
gem "kamal", ">= 2.0.0.rc2", require: false

# Cross-platform compatibility
gem "tzinfo-data", platforms: %i[ windows jruby ]

group :development, :test do
  # Debugging
  gem "debug", platforms: %i[ mri windows ], require: "debug/prelude"

  # Code quality and security
  gem "brakeman", require: false
  gem "rubocop-rails-omakase", require: false
  gem "annotate"
  gem "pry-rails"
end
