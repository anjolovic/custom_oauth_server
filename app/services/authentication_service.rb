class AuthenticationService
  def self.authenticate_client(client_id:, client_secret:)
    client = OAuthClient.find_by(client_id: client_id)
    return client if client&.authenticate(client_secret)
    nil
  end

  def self.authenticate_request(token)
    return nil unless token

    begin
      decoded_token = JWT.decode(
        token, 
        Rails.application.secret_key_base, 
        true, 
        { algorithm: 'HS256' }
      )
      User.find(decoded_token[0]['sub'])
    rescue JWT::DecodeError, ActiveRecord::RecordNotFound
      nil
    end
  end
end
