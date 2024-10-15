require "test_helper"

class Api::V1::OauthControllerTest < ActionDispatch::IntegrationTest
  setup do
    @client = o_auth_clients(:one)
    @user = users(:one)
    @scope = Scope.create!(name: "read", description: "Read access")
    @code_verifier = SecureRandom.hex(32)
    @code_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(@code_verifier)).tr('=', '')
  end

  test "should get authorization code" do
    get api_v1_oauth_authorize_url, params: {
      client_id: @client.client_id,
      redirect_uri: @client.redirect_uri,
      response_type: 'code',
      scope: 'read',
      code_challenge: @code_challenge,
      code_challenge_method: 'S256'
    }
    assert_response :redirect
    assert_match /code=/, @response.location
    assert_redirected_to %r{\A#{@client.redirect_uri}}, allow_other_host: true
  end

  test "should exchange authorization code for tokens" do
    auth_code = AuthorizationCode.create!(
      code: "valid_code",
      o_auth_client: @client,
      user: @user,
      redirect_uri: @client.redirect_uri,
      expires_at: 10.minutes.from_now,
      code_challenge: @code_challenge,
      code_challenge_method: "S256",
      scopes: ["read"]
    )

    post api_v1_oauth_token_url, params: {
      grant_type: 'authorization_code',
      code: auth_code.code,
      client_id: @client.client_id,
      client_secret: @client.client_secret,
      redirect_uri: @client.redirect_uri,
      code_verifier: @code_verifier
    }

    assert_response :success
    assert_not_nil JSON.parse(@response.body)['access_token']
    assert_not_nil JSON.parse(@response.body)['refresh_token']
  end

  test "should refresh token" do
    refresh_token = OAuthRefreshToken.create!(
      token: "valid_refresh_token",
      o_auth_client: @client,
      user: @user,
      expires_at: 30.days.from_now,
      scopes: ["read"]
    )

    post api_v1_oauth_token_url, params: {
      grant_type: 'refresh_token',
      refresh_token: refresh_token.token,
      client_id: @client.client_id,
      client_secret: @client.client_secret
    }

    assert_response :success
    assert_not_nil JSON.parse(@response.body)['access_token']
  end

  test "should revoke token" do
    access_token = OAuthAccessToken.create!(
      token: "valid_access_token",
      o_auth_client: @client,
      user: @user,
      expires_at: 1.hour.from_now
    )

    post api_v1_oauth_revoke_url, params: {
      token: access_token.token,
      client_id: @client.client_id,
      client_secret: @client.client_secret
    }

    assert_response :success
    assert access_token.reload.revoked?
  end
end