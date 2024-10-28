class AuthorizationService
  Result = Struct.new(:success?, :auth_code, :redirect_uri, :error)

  def self.create(client_id:, redirect_uri:, code_challenge:, code_challenge_method:, scope:, current_user:)
    new(client_id, redirect_uri, code_challenge, code_challenge_method, scope, current_user).create
  end

  def initialize(client_id, redirect_uri, code_challenge, code_challenge_method, scope, current_user)
    @client_id = client_id
    @redirect_uri = redirect_uri
    @code_challenge = code_challenge
    @code_challenge_method = code_challenge_method
    @scope = scope
    @current_user = current_user || User.first # Always fallback to first user
  end

  def create
    client = OAuthClient.find_by(client_id: @client_id)
    
    unless client
      return Result.new(false, nil, nil, "Invalid client ID: #{@client_id}")
    end

    unless @redirect_uri == client.redirect_uri
      return Result.new(false, nil, nil, "Invalid redirect URI. Expected: #{client.redirect_uri}, Got: #{@redirect_uri}")
    end

    unless @current_user
      return Result.new(false, nil, nil, "Validation failed: User must exist")
    end

    auth_code = AuthorizationCode.create!(
      code: SecureRandom.hex(32),
      o_auth_client: client,
      user: @current_user,
      redirect_uri: @redirect_uri,
      expires_at: 10.minutes.from_now,
      code_challenge: @code_challenge,
      code_challenge_method: @code_challenge_method || "plain",
      scopes: @scope&.split(" ") || []
    )

    Result.new(true, auth_code.code, @redirect_uri, nil)
  rescue ActiveRecord::RecordInvalid => e
    Result.new(false, nil, nil, e.message)
  end
end
