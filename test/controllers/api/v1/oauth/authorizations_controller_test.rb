require 'test_helper'

module Api
  module V1
    module Oauth
      class AuthorizationsControllerTest < ActionDispatch::IntegrationTest
        setup do
          @client = o_auth_clients(:valid)
          @user = users(:john)
          @access_token = OAuthAccessToken.create!(
            token: SecureRandom.hex(32),
            user: @user,
            o_auth_client: @client,
            expires_at: 1.hour.from_now,
            scopes: ['read', 'write']
          )
          @headers = { 
            'Authorization': "Bearer #{@access_token.token}",
            'Accept': 'application/json'
          }
        end

        test "creates authorization code with valid parameters" do
          # Create a new access token for this specific test
          access_token = OAuthAccessToken.create!(
            token: SecureRandom.hex(32),
            user: @user,
            o_auth_client: @client,
            expires_at: 1.hour.from_now,
            scopes: ['read', 'write']
          )

          auth_header = "Bearer #{access_token.token}"

          # Verify token is valid before making request
          assert AuthenticationService.verify_token(access_token.token), "Token should be valid"
          assert_equal @user, AuthenticationService.authenticate_request(access_token.token), "Should authenticate user"

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
              'Authorization': auth_header,
              'Accept': 'application/json'
            }

          if response.status != 302
            debug_response
            puts "Authorization Header: #{auth_header}"
            puts "Access Token Valid: #{access_token.expires_at > Time.current}"
            puts "Access Token: #{access_token.inspect}"
            puts "Current User from Token: #{AuthenticationService.authenticate_request(access_token.token)&.inspect}"
            puts "Token Info: #{AuthenticationService.get_token_info(access_token.token)&.inspect}"
          end

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
          puts "Current User: #{@user.inspect}"
          puts "Access Token: #{@access_token.inspect}"
          puts "Authorization Header: #{@headers['Authorization']}"
        end
      end
    end
  end
end
