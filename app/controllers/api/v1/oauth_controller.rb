module Api
# Brief explanation:
# This OauthController handles the core OAuth flows:
# authorization code grant, refresh token, and client credentials. The controller includes methods for
# authorizing clients, issuing tokens, refreshing tokens, and revoking tokens. It also implements security
# features like PKCE (Proof Key for Code Exchange) and scope validation. The controller uses JWT (JSON Web Tokens)
# for access tokens, providing a stateless authentication mechanism. This implementation allows applications
# to securely authenticate and authorize users or other applications, following OAuth 2.0 standards and best practices.
  module V1
    class OauthController < ActionController::API 
      # Handles the authorization request
      def authorize
        client = OAuthClient.find_by(client_id: params[:client_id])
        if client && params[:redirect_uri] == client.redirect_uri
          # Generate and store an authorization code
          auth_code = AuthorizationCode.create!(
            code: SecureRandom.hex(32),
            o_auth_client: client,
            user: User.first, # TODO: Replace with actual user authentication
            redirect_uri: params[:redirect_uri],
            expires_at: 10.minutes.from_now,
            code_challenge: params[:code_challenge],
            code_challenge_method: params[:code_challenge_method] || 'plain',
            scopes: params[:scope]&.split(' ') || []
          )

          # Use redirect_to with allow_other_host: true
          redirect_to "#{params[:redirect_uri]}?code=#{auth_code.code}", allow_other_host: true
        else
          render json: { error: 'Invalid client or redirect URI' }, status: :unauthorized
        end
      end

      # Handles token requests
      def token
        client = authenticate_client
        return unless client

        case params[:grant_type]
        when 'authorization_code'
          handle_authorization_code(client)
        when 'refresh_token'
          handle_refresh_token(client)
        when 'client_credentials'
          handle_client_credentials(client)
        else
          render json: { error: 'Unsupported grant type' }, status: :bad_request
        end
      end

      # Revokes a token
      def revoke
        token = OAuthAccessToken.find_by(token: params[:token]) || OAuthRefreshToken.find_by(token: params[:token])
        if token
          token.update!(revoked_at: Time.current)
          head :ok
        else
          render json: { error: 'Token not found' }, status: :not_found
        end
      end

      # Handles the authorization code grant type
      def handle_authorization_code(client)
        auth_code = AuthorizationCode.find_by(code: params[:code])
        if auth_code && !auth_code.expired? && auth_code.o_auth_client_id == client.id
          # Verify PKCE
          if auth_code.code_challenge.present?
            unless verify_code_verifier(auth_code.code_challenge, params[:code_verifier], auth_code.code_challenge_method)
              return render json: { error: 'Invalid code verifier' }, status: :unauthorized
            end
          end

          requested_scopes = params[:scope]&.split(' ') || []
          unless validate_scopes(requested_scopes)
            return render json: { error: 'Invalid scopes requested' }, status: :bad_request
          end

          user = auth_code.user
          access_token = OAuthAccessToken.create!(
            token: SecureRandom.hex(32),
            expires_at: 1.hour.from_now,
            o_auth_client: client,
            user: user,
            scopes: auth_code.scopes
          )
          refresh_token = OAuthRefreshToken.create!(
            token: SecureRandom.hex(32),
            expires_at: 30.days.from_now,
            o_auth_client: client,
            user: user,
            scopes: auth_code.scopes
          )
          auth_code.destroy!

          jwt_token = generate_jwt(user, auth_code.scopes)
          render json: {
            access_token: jwt_token,
            token_type: 'Bearer',
            expires_in: 3600,
            refresh_token: refresh_token.token,
            scope: auth_code.scopes.join(' ')
          }
        else
          render json: { error: 'Invalid authorization code' }, status: :unauthorized
        end
      end

      # Handles the refresh token grant type
      def handle_refresh_token(client)
        refresh_token = OAuthRefreshToken.find_by(token: params[:refresh_token])
        if refresh_token && !refresh_token.revoked? && refresh_token.o_auth_client_id == client.id
          access_token = OAuthAccessToken.create!(
            token: SecureRandom.hex(32),
            expires_at: 1.hour.from_now,
            o_auth_client: client,
            user: refresh_token.user,
            scopes: refresh_token.scopes
          )
          refresh_token.update!(expires_at: 30.days.from_now)

          render json: {
            access_token: access_token.token,
            token_type: 'Bearer',
            expires_in: access_token.expires_in,
            refresh_token: refresh_token.token,
            scope: access_token.scopes.join(' ')
          }
        else
          render json: { error: 'Invalid refresh token' }, status: :unauthorized
        end
      end

      # Handles the client credentials grant type
      def handle_client_credentials(client)
        access_token = OAuthAccessToken.create!(
          token: SecureRandom.hex(32),
          expires_at: 1.hour.from_now,
          o_auth_client: client,
          user: nil,
          scopes: params[:scope]&.split(' ') || []
        )

        render json: {
          access_token: access_token.token,
          token_type: 'Bearer',
          expires_in: access_token.expires_in,
          scope: access_token.scopes.join(' ')
        }
      end

      # Verifies the code verifier for PKCE
      def verify_code_verifier(challenge, verifier, method)
        case method
        when 'plain'
          challenge == verifier
        when 'S256'
          challenge == Base64.urlsafe_encode64(Digest::SHA256.digest(verifier)).tr('=', '')
        else
          false
        end
      end

      # Validates the requested scopes
      def validate_scopes(requested_scopes)
        available_scopes = Scope.pluck(:name)
        requested_scopes.all? { |scope| available_scopes.include?(scope) }
      end

      # Generates a JWT token
      def generate_jwt(user, scopes)
        payload = {
          sub: user.id,
          scopes: scopes,
          exp: 1.hour.from_now.to_i
        }
        JWT.encode(payload, Rails.application.credentials.secret_key_base, 'HS256')
      end

      def login
        # Render a login page or redirect to an external authentication service
        # This could be a simple form or integration with services like Google, Apple, or Login.gov
      end

      def create_account
        # Render a page for creating a new account
      end

      def user_info
        # Ensure the user is authenticated
        user = authenticate_request
        if user
          render json: {
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name
          }
        else
          render json: { error: 'Unauthorized' }, status: :unauthorized
        end
      end

      # Handles logout
      def logout
        token = request.headers['Authorization']&.split(' ')&.last
        if token
          access_token = OAuthAccessToken.find_by(token: token)
          if access_token
            access_token.revoke!
            OAuthRefreshToken.where(user: access_token.user, o_auth_client: access_token.o_auth_client).update_all(revoked_at: Time.current)
            render json: { message: 'Logged out successfully' }
          else
            render json: { error: 'Invalid token' }, status: :unauthorized
          end
        else
          render json: { error: 'No token provided' }, status: :bad_request
        end
      end

      private

      # Authenticates the client
      def authenticate_client
        client = OAuthClient.find_by(client_id: params[:client_id])
        if client && client.authenticate(params[:client_secret])
          client
        else
          render json: { error: 'Invalid client credentials' }, status: :unauthorized
          nil
        end
      end

      # Authenticates the request
      def authenticate_request
        # Implement token-based authentication
        # Return the user if authenticated, nil otherwise
      end

      # Verifies the code verifier for PKCE
      def verify_code_verifier(challenge, verifier, method)
        case method
        when 'plain'
          challenge == verifier
        when 'S256'
          challenge == Base64.urlsafe_encode64(Digest::SHA256.digest(verifier)).tr('=', '')
        else
          false
        end
      end

      # Validates the requested scopes
      def validate_scopes(requested_scopes)
        available_scopes = Scope.pluck(:name)
        requested_scopes.all? { |scope| available_scopes.include?(scope) }
      end

      # Generates a JWT token
      def generate_jwt(user, scopes)
        payload = {
          sub: user.id,
          scopes: scopes,
          exp: 1.hour.from_now.to_i
        }
        JWT.encode(payload, Rails.application.credentials.secret_key_base, 'HS256')
      end

      def login
        # Render a login page or redirect to an external authentication service
        # This could be a simple form or integration with services like Google, Apple, or Login.gov
      end

      def create_account
        # Render a page for creating a new account
      end
    end
  end
end