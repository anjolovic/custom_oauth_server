class TokenService
  Result = Struct.new(:success?, :response, :error, :status)

  def self.create(client:, grant_type:, params:)
    new(client, grant_type, params).create
  end

  def self.revoke(token:)
    new(nil, nil, token: token).revoke
  end

  def initialize(client, grant_type, params)
    @client = client
    @grant_type = grant_type
    @params = params
  end

  def create
    case @grant_type
    when "authorization_code"
      handle_authorization_code
    when "refresh_token"
      handle_refresh_token
    when "client_credentials"
      handle_client_credentials
    else
      Result.new(false, nil, "Unsupported grant type", :bad_request)
    end
  end

  def revoke
    token = OAuthAccessToken.find_by(token: @params[:token]) || 
            OAuthRefreshToken.find_by(token: @params[:token])

    if token
      token.update!(revoked_at: Time.current)
      Result.new(true, nil, nil, :ok)
    else
      Result.new(false, nil, "Token not found", :not_found)
    end
  end

  private

  def handle_authorization_code
    auth_code = AuthorizationCode.find_by(code: @params[:code])
    
    Rails.logger.debug "Auth code: #{auth_code.inspect}"
    Rails.logger.debug "Client: #{@client.inspect}"
    Rails.logger.debug "Params: #{@params.inspect}"
    
    return invalid_auth_code_response unless valid_auth_code?(auth_code)
    return invalid_code_verifier_response unless valid_code_verifier?(auth_code)
    
    create_tokens_for_auth_code(auth_code)
  rescue StandardError => e
    Rails.logger.error "Error in handle_authorization_code: #{e.message}"
    Rails.logger.error e.backtrace.join("\n")
    Result.new(false, nil, "Error processing authorization code: #{e.message}", :internal_server_error)
  end

  def handle_refresh_token
    refresh_token = find_refresh_token
    return missing_refresh_token_response if refresh_token.blank?
    
    oauth_refresh_token = OAuthRefreshToken.find_by(token: refresh_token)
    return invalid_refresh_token_response unless valid_refresh_token?(oauth_refresh_token)
    
    create_tokens_for_refresh_token(oauth_refresh_token)
  end

  def handle_client_credentials
    access_token = OAuthAccessToken.create!(
      token: SecureRandom.hex(32),
      expires_at: 1.hour.from_now,
      o_auth_client: @client,
      user: nil,
      scopes: @params[:scope]&.split(" ") || []
    )

    Result.new(true, {
      access_token: access_token.token,
      token_type: "Bearer",
      expires_in: access_token.expires_in,
      scope: access_token.scopes.join(" ")
    })
  end

  # Add other helper methods...

  def valid_auth_code?(auth_code)
    return false unless auth_code
    return false if auth_code.expired?
    return false unless auth_code.o_auth_client_id == @client.id
    true
  end

  def valid_code_verifier?(auth_code)
    return true unless auth_code.code_challenge.present?
    
    verify_code_verifier(
      auth_code.code_challenge,
      @params[:code_verifier],
      auth_code.code_challenge_method
    )
  end

  def verify_code_verifier(challenge, verifier, method)
    case method
    when "plain"
      challenge == verifier
    when "S256"
      challenge == Base64.urlsafe_encode64(Digest::SHA256.digest(verifier)).tr("=", "")
    else
      false
    end
  end

  def find_refresh_token
    @params[:refresh_token] || @params.dig(:oauth, :refresh_token)
  end

  def valid_refresh_token?(token)
    token && !token.revoked? && token.o_auth_client_id == @client.id
  end

  def create_tokens_for_auth_code(auth_code)
    user = auth_code.user
    access_token = OAuthAccessToken.create!(
      token: SecureRandom.hex(32),
      expires_at: 1.hour.from_now,
      o_auth_client: @client,
      user: user,
      scopes: auth_code.scopes
    )
    
    refresh_token = OAuthRefreshToken.create!(
      token: SecureRandom.hex(32),
      expires_at: 30.days.from_now,
      o_auth_client: @client,
      user: user,
      scopes: auth_code.scopes
    )

    auth_code.destroy!

    Result.new(true, {
      access_token: access_token.token,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: refresh_token.token,
      scope: auth_code.scopes.join(" ")
    })
  end

  def create_tokens_for_refresh_token(refresh_token)
    user = refresh_token.user
    access_token = OAuthAccessToken.create!(
      token: SecureRandom.hex(32),
      expires_at: 1.hour.from_now,
      o_auth_client: @client,
      user: user,
      scopes: refresh_token.scopes
    )

    refresh_token.update!(expires_at: 30.days.from_now)

    Result.new(true, {
      access_token: access_token.token,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: refresh_token.token,
      scope: refresh_token.scopes.join(" ")
    })
  end

  def invalid_auth_code_response
    Result.new(false, nil, "Invalid authorization code", :unauthorized)
  end

  def invalid_code_verifier_response
    Result.new(false, nil, "Invalid code verifier", :unauthorized)
  end

  def missing_refresh_token_response
    Result.new(false, nil, "Refresh token is missing", :bad_request)
  end

  def invalid_refresh_token_response
    Result.new(false, nil, "Invalid refresh token", :unauthorized)
  end
end
