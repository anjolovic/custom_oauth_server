ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"

module ActiveSupport
  class TestCase
    include ActionDispatch::TestProcess
    
    # Run tests in parallel with specified workers
    parallelize(workers: :number_of_processors)

    # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
    fixtures :all

    # Add more helper methods to be used by all tests here...
    def client_secret_for(client_name)
      @client_secrets ||= {}
      @client_secrets[client_name] ||= SecureRandom.hex(32).tap do |secret|
        client = o_auth_clients(client_name)
        client.update!(client_secret: secret)
      end
    end

    def authenticate_as(user, client = nil)
      client ||= o_auth_clients(:valid)
      token = OAuthAccessToken.create!(
        token: SecureRandom.hex(32),
        user: user,
        o_auth_client: client,
        expires_at: 1.hour.from_now,
        scopes: ['read', 'write']
      )
      token.token
    end

    def auth_headers(user = nil, client = nil)
      return {} unless user
      {'Authorization': "Bearer #{authenticate_as(user, client)}"}
    end
  end
end
