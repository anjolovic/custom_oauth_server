require 'test_helper'

module Api
  module V1
    module Oauth
      class SessionsControllerTest < ActionDispatch::IntegrationTest
        setup do
          @user = users(:john)
          @client = o_auth_clients(:valid)
          @oauth_params = {
            client_id: @client.client_id,
            redirect_uri: "http://localhost:3000/callback",
            code_challenge: "challenge",
            code_challenge_method: "plain",
            scope: "read write",
            state: "some_state"
          }
        end

        test "creates session with valid credentials" do
          post api_v1_oauth_session_path, params: {
            email: @user.email,
            password: 'password123',
            client_id: @client.client_id
          }

          assert_response :success
          assert_not_nil JSON.parse(response.body)["token"]
        end

        test "creates session with valid credentials and oauth params" do
          post api_v1_oauth_session_path, params: {
            email: @user.email,
            password: 'password123',
            return_to: authorize_api_v1_oauth_authorization_path
          }.merge(@oauth_params)

          assert_response :success
          response_body = JSON.parse(response.body)
          assert_not_nil response_body["token"]
          assert_equal authorize_api_v1_oauth_authorization_path, response_body["redirect_to"]
        end

        test "fails with invalid credentials" do
          post api_v1_oauth_session_path, params: {
            email: @user.email,
            password: 'wrong_password'
          }

          assert_response :unauthorized
          assert_equal "Invalid email or password", JSON.parse(response.body)["error"]
        end

        test "destroys session successfully" do
          access_token = OAuthAccessToken.create!(
            token: SecureRandom.hex(32),
            o_auth_client: o_auth_clients(:valid),
            user: @user,
            expires_at: 1.hour.from_now
          )

          delete api_v1_oauth_session_path, headers: {
            'Authorization': "Bearer #{access_token.token}"
          }

          assert_response :success
          assert_equal "Logged out successfully", JSON.parse(response.body)["message"]
        end

        test "redirects to authorization after successful login with oauth params" do
          post api_v1_oauth_session_path, params: {
            email: @user.email,
            password: 'password123',
            return_to: authorize_api_v1_oauth_authorization_path
          }.merge(@oauth_params)

          assert_response :success
          response_body = JSON.parse(response.body)
          assert_not_nil response_body["token"]
          assert_equal authorize_api_v1_oauth_authorization_path, response_body["redirect_to"]
        end
      end
    end
  end
end
