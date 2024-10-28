require_relative "boot"

require "rails/all"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module CustomOauthServer
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 7.1
    
    # Enable sessions
    config.middleware.use ActionDispatch::Cookies
    config.middleware.use ActionDispatch::Session::CookieStore
    
    # API configuration
    config.api_only = false # Change this to false to enable session support

    # Handle deprecation warning
    config.active_support.to_time_preserves_timezone = :zone
  end
end
