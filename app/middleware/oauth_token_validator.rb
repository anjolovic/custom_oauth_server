class OauthTokenValidator
  def initialize(app)
    @app = app
  end

  def call(env)
    request = Rack::Request.new(env)
    auth_header = request.get_header('HTTP_AUTHORIZATION')
    if auth_header && auth_header.start_with?('Bearer ')
      token = auth_header.split(' ').last
      access_token = OAuthAccessToken.find_by(token: token)
      if access_token && !access_token.expired?
        env['oauth_token'] = access_token
      end
    end
    @app.call(env)
  end
end