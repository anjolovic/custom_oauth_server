require 'test_helper'

module Api
  module V1
    module Oauth
      class AuthorizationsControllerTest < ActionDispatch::IntegrationTest
        setup do
          @client = o_auth_clients(:valid)
          @user = users(:john)
          @token = authenticate_as(@user, @client)
          @headers = { 
            'Authorization': "Bearer #{@token}",
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          }
        end

        test "creates authorization code with valid parameters" do
          # Create access token for authentication
          access_token = OAuthAccessToken.create!(
            token: SecureRandom.hex(32),
            user: @user,
            o_auth_client: @client,
            expires_at: 1.hour.from_now,
            scopes: ['read', 'write']
          )

          get authorize_api_v1_oauth_authorization_path, 
            params: {
              client_id: @client.client_id,
              redirect_uri: @client.redirect_uri,
              code_challenge: "challenge",
              code_challenge_method: "plain",
              scope: "read write",
              state: "some_state"
            },
            headers: { 
              'Authorization': "Bearer #{access_token.token}",
              'Accept': 'application/json'
            }

          assert_response :redirect
          assert_match /code=/, response.location
          assert_match /state=some_state/, response.location
        end

        test "returns error with invalid client" do
          get authorize_api_v1_oauth_authorization_path, 
            params: {
              client_id: "invalid",
              redirect_uri: @client.redirect_uri
            },
            headers: @headers

          assert_response :unauthorized
          assert_equal "Invalid client ID: invalid", JSON.parse(response.body)["error"]
        end

        test "returns error with invalid redirect uri" do
          get authorize_api_v1_oauth_authorization_path, 
            params: {
              client_id: @client.client_id,
              redirect_uri: "http://wrong.url"
            },
            headers: @headers

          assert_response :unauthorized
          assert_equal(
            "Invalid redirect URI. Expected: #{@client.redirect_uri}, Got: http://wrong.url",
            JSON.parse(response.body)["error"]
          )
        end

        test "returns login required without authentication" do
          get authorize_api_v1_oauth_authorization_path, 
            params: {
              client_id: @client.client_id,
              redirect_uri: @client.redirect_uri
            }

          assert_response :unauthorized
          response_body = JSON.parse(response.body)
          assert_equal "Login required", response_body["error"]
          assert_not_nil response_body["login_url"]
        end

        private

        def debug_response
          puts "\nResponse Status: #{response.status}"
          puts "Response Body: #{response.body}"
          puts "Response Headers: #{response.headers}"
          puts "Request Headers: #{@headers}"
        end
      end
    end
  end
end
