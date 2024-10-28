require 'test_helper'

module Api
  module V1
    module Oauth
      class TokensControllerTest < ActionDispatch::IntegrationTest
        setup do
          @client = o_auth_clients(:valid)
          @user = users(:john)
          @client_secret = client_secret_for(:valid)
        end

        test "refreshes token with valid refresh token" do
          refresh_token = OAuthRefreshToken.create!(
            token: SecureRandom.hex(32),
            o_auth_client: @client,
            user: @user,
            expires_at: 30.days.from_now,
            scopes: ['read', 'write']
          )

          post api_v1_oauth_tokens_path, 
            params: {
              grant_type: 'refresh_token',
              refresh_token: refresh_token.token,
              client_id: @client.client_id,
              client_secret: @client_secret
            },
            headers: { 'Accept': 'application/json' }

          assert_response :success
          response_body = JSON.parse(response.body)
          assert_not_nil response_body["access_token"]
          assert_not_nil response_body["refresh_token"]
          assert_equal "Bearer", response_body["token_type"]
          assert_equal 3600, response_body["expires_in"]
          assert_not_nil response.headers["Authorization"]
        end

        test "returns error with invalid refresh token" do
          post api_v1_oauth_tokens_path, 
            params: {
              grant_type: 'refresh_token',
              refresh_token: 'invalid_token',
              client_id: @client.client_id,
              client_secret: @client.client_secret
            },
            headers: { 'Accept': 'application/json' }

          assert_response :unauthorized
          assert_equal "Invalid refresh token", JSON.parse(response.body)["error"]
        end
      end
    end
  end
end
