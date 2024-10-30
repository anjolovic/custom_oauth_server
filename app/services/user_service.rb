class UserService
  Result = Struct.new(:success?, :user, :token, :errors)

  def self.create(params)
    new(params).create
  end

  def initialize(params)
    @params = params
    @client_id = params.delete(:client_id)
  end

  def create
    user = User.new(@params)
    
    if user.save
      client = if @client_id
                OAuthClient.find_by(client_id: @client_id)
              else
                OAuthClient.first
              end

      # Create access token for the new user
      access_token = OAuthAccessToken.create!(
        token: SecureRandom.hex(32),
        user: user,
        o_auth_client: client,
        expires_at: 1.hour.from_now,
        scopes: ['read', 'write']
      )
      
      Result.new(true, user, access_token.token, nil)
    else
      Result.new(false, nil, nil, user.errors.full_messages)
    end
  rescue StandardError => e
    Result.new(false, nil, nil, [e.message])
  end
end
