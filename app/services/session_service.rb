class SessionService
  Result = Struct.new(:success?, :token, :error, :status)

  def self.create(email:, password:)
    new(email, password).create
  end

  def self.destroy(token:)
    new(nil, nil, token).destroy
  end

  def initialize(email, password, token = nil)
    @email = email
    @password = password
    @token = token
  end

  def create
    user = User.find_by(email: @email.downcase)

    if user&.authenticate(@password)
      access_token = create_access_token(user)
      Result.new(true, access_token.token, nil)
    else
      Result.new(false, nil, "Invalid email or password")
    end
  end

  def destroy
    return Result.new(false, nil, "No token provided", :bad_request) unless @token

    access_token = OAuthAccessToken.find_by(token: @token)
    if access_token
      access_token.update!(revoked_at: Time.current)
      Result.new(true, nil, nil)
    else
      Result.new(false, nil, "Invalid token", :unauthorized)
    end
  end

  private

  def create_access_token(user)
    OAuthAccessToken.create!(
      token: SecureRandom.hex(32),
      user: user,
      o_auth_client: OAuthClient.first, # Use first client for now
      expires_at: 1.hour.from_now,
      scopes: ['read', 'write']
    )
  end
end
