class AuthenticationService
  def self.authenticate_client(client_id:, client_secret:)
    client = OAuthClient.find_by(client_id: client_id)
    return nil unless client&.authenticate(client_secret)
    client
  end

  def self.authenticate_request(token)
    return nil unless token

    access_token = OAuthAccessToken.find_by(token: token)
    return nil unless access_token
    return nil if access_token.expired?
    return nil if access_token.revoked?

    access_token.user
  end

  def self.authenticate_user(email, password)
    user = User.find_by(email: email.downcase)
    return nil unless user&.authenticate(password)
    user
  end

  def self.verify_token(token)
    access_token = OAuthAccessToken.find_by(token: token)
    return false unless access_token
    return false if access_token.expired?
    return false if access_token.revoked?
    true
  end

  def self.get_token_info(token)
    access_token = OAuthAccessToken.find_by(token: token)
    return nil unless access_token
    return nil if access_token.expired?
    return nil if access_token.revoked?

    {
      user: access_token.user,
      client: access_token.o_auth_client,
      scopes: access_token.scopes,
      expires_at: access_token.expires_at
    }
  end

  private

  def self.token_from_header(header)
    return nil unless header
    header.split(' ').last
  end
end
