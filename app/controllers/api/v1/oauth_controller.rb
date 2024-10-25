module Api
  module V1
    class OauthController < ActionController::API
      # Handles the authorization request
      # Creates an authorization code if the client and redirect URI are valid
      # Handles the authorization request
      # Creates an authorization code if the client and redirect URI are valid
      def authorize
        # It performs the following steps:
        # 1. Validates the client and redirect URI
        # 2. Creates an authorization code with various parameters
        # 3. Redirects the user to the client's redirect URI with the authorization code
        # If validation fails, it returns an error response
        client = OAuthClient.find_by(client_id: params[:client_id])
        if client && params[:redirect_uri] == client.redirect_uri
          auth_code = AuthorizationCode.create!(
            code: SecureRandom.hex(32),
            o_auth_client: client,
            user: current_user || User.first,
            redirect_uri: params[:redirect_uri],
            expires_at: 10.minutes.from_now,
            code_challenge: params[:code_challenge],
            code_challenge_method: params[:code_challenge_method] || "plain",
            scopes: params[:scope]&.split(" ") || []
          )
          redirect_to "#{params[:redirect_uri]}?code=#{auth_code.code}", allow_other_host: true
        else
          render json: { error: "Invalid client or redirect URI" }, status: :unauthorized
        end
      end

      # Handles token requests
      # Supports authorization_code, refresh_token, and client_credentials grant types
      def token
        # It performs the following steps:
        # 1. Authenticates the client
        # 2. Handles different grant types (authorization_code, refresh_token, client_credentials)
        # 3. Calls the appropriate handler method based on the grant type
        # If authentication fails or the grant type is unsupported, it returns an error response
        client = authenticate_client
        return unless client

        case params[:grant_type]
        when "authorization_code"
          handle_authorization_code(client)
        when "refresh_token"
          handle_refresh_token(client)
        when "client_credentials"
          handle_client_credentials(client)
        else
          render json: { error: "Unsupported grant type" }, status: :bad_request
        end
      end

      # Revokes the given access or refresh token
      def revoke
        # It performs the following steps:
        # 1. Finds the token (access or refresh) by the provided token value
        # 2. If found, revokes the token by updating its revoked_at timestamp
        # 3. Returns a success response if revoked, or an error if the token is not found
        token = OAuthAccessToken.find_by(token: params[:token]) || OAuthRefreshToken.find_by(token: params[:token])
        if token
          token.update!(revoked_at: Time.current)
          head :ok
        else
          render json: { error: "Token not found" }, status: :not_found
        end
      end

      # Handles user login
      # Authenticates the user and returns a JWT token
      def login
        # It performs the following steps:
        # 1. Finds the user by email
        # 2. Authenticates the user with the provided password
        # 3. If authentication succeeds, generates a JWT token with read and write scopes
        # 4. Returns the JWT token or an error response if authentication fails
        user = User.find_by(email: params[:email])
        if user&.authenticate(params[:password])
          jwt_token = generate_jwt(user, ["read", "write"])
          render json: { token: jwt_token }
        else
          render json: { error: "Invalid email or password" }, status: :unauthorized
        end
      end

      # Handles user account creation
      # Creates a new user and returns a JWT token
      def create_account
        # It performs the following steps:
        # 1. Creates a new user with the provided parameters
        # 2. If the user is saved successfully, generates a JWT token with read and write scopes
        # 3. Returns the JWT token or validation errors if user creation fails
        user = User.new(user_params)
        if user.save
          jwt_token = generate_jwt(user, ["read", "write"])
          render json: { token: jwt_token }, status: :created
        else
          render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
        end
      end

      # Returns user information for the authenticated user
      def user_info
        # It performs the following steps:
        # 1. Authenticates the request to get the current user
        # 2. If authentication succeeds, returns the user's email, first name, and last name
        # 3. If authentication fails, returns an unauthorized error response
        user = authenticate_request
        if user
          render json: {
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name
          }
        else
          render json: { error: "Unauthorized" }, status: :unauthorized
        end
      end

      # Handles user logout
      # Revokes the access token and associated refresh tokens
      def logout
        # It performs the following steps:
        # 1. Extracts the access token from the Authorization header
        # 2. Finds the corresponding access token in the database
        # 3. If found, revokes the access token and associated refresh tokens for the user and client
        # 4. Returns a success message or an error response if the token is invalid or not provided
        token = request.headers["Authorization"]&.split(" ")&.last
        if token
          access_token = OAuthAccessToken.find_by(token: token)
          if access_token
            access_token.revoke!
            OAuthRefreshToken.where(user: access_token.user, o_auth_client: access_token.o_auth_client).update_all(revoked_at: Time.current)
            render json: { message: "Logged out successfully" }
          else
            render json: { error: "Invalid token" }, status: :unauthorized
          end
        else
          render json: { error: "No token provided" }, status: :bad_request
        end
      end

      private

      # Handles the authorization code grant type
      # Verifies the code and creates access and refresh tokens
      def handle_authorization_code(client)
        auth_code = AuthorizationCode.find_by(code: params[:code])
        if auth_code && !auth_code.expired? && auth_code.o_auth_client_id == client.id
          if auth_code.code_challenge.present?
            unless verify_code_verifier(auth_code.code_challenge, params[:code_verifier], auth_code.code_challenge_method)
              return render json: { error: "Invalid code verifier" }, status: :unauthorized
            end
          end

          requested_scopes = params[:scope]&.split(" ") || []
          unless validate_scopes(requested_scopes)
            return render json: { error: "Invalid scopes requested" }, status: :bad_request
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
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: refresh_token.token,
            scope: auth_code.scopes.join(" ")
          }
        else
          render json: { error: "Invalid authorization code" }, status: :unauthorized
        end
      end

      # Handles the refresh token grant type
      # Verifies the refresh token and creates a new access token
      def handle_refresh_token(client)
        refresh_token = params[:refresh_token] || params.dig(:oauth, :refresh_token) || request.headers['HTTP_REFRESH_TOKEN']
        
        if refresh_token.blank?
          render json: { error: "Refresh token is missing" }, status: :bad_request
          return
        end

        oauth_refresh_token = OAuthRefreshToken.find_by(token: refresh_token)
        
        if oauth_refresh_token && !oauth_refresh_token.revoked? && oauth_refresh_token.o_auth_client_id == client.id
          user = oauth_refresh_token.user
          access_token = OAuthAccessToken.create!(
            token: SecureRandom.hex(32),
            expires_at: 1.hour.from_now,
            o_auth_client: client,
            user: user,
            scopes: oauth_refresh_token.scopes
          )
          oauth_refresh_token.update!(expires_at: 30.days.from_now)

          jwt_token = generate_jwt(user, oauth_refresh_token.scopes)
          render json: {
            access_token: jwt_token,
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: oauth_refresh_token.token,
            scope: oauth_refresh_token.scopes.join(" ")
          }
        else
          render json: { error: "Invalid refresh token" }, status: :unauthorized
        end
      end

      # Handles the client credentials grant type
      # Creates an access token for the client
      def handle_client_credentials(client)
        access_token = OAuthAccessToken.create!(
          token: SecureRandom.hex(32),
          expires_at: 1.hour.from_now,
          o_auth_client: client,
          user: nil,
          scopes: params[:scope]&.split(" ") || []
        )

        render json: {
          access_token: access_token.token,
          token_type: "Bearer",
          expires_in: access_token.expires_in,
          scope: access_token.scopes.join(" ")
        }
      end

      # Authenticates the OAuth client
      def authenticate_client
        client = OAuthClient.find_by(client_id: params[:client_id])
        if client && client.authenticate(params[:client_secret])
          client
        else
          render json: { error: "Invalid client credentials" }, status: :unauthorized
          nil
        end
      end

      # Authenticates the request using the JWT token in the Authorization header
      def authenticate_request
        auth_header = request.headers['Authorization']
        if auth_header
          token = auth_header.split(' ').last
          begin
            decoded_token = JWT.decode(token, Rails.application.secret_key_base, true, { algorithm: 'HS256' })
            User.find(decoded_token[0]['sub'])
          rescue JWT::DecodeError, ActiveRecord::RecordNotFound
            nil
          end
        end
      end

      # Verifies the code verifier for PKCE
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

      # Validates the requested scopes against available scopes
      def validate_scopes(requested_scopes)
        available_scopes = Scope.pluck(:name)
        requested_scopes.all? { |scope| available_scopes.include?(scope) }
      end

      # Generates a JWT token for the given user and scopes
      def generate_jwt(user, scopes)
        payload = {
          sub: user.id,
          scopes: scopes,
          exp: 1.hour.from_now.to_i
        }
        JWT.encode(payload, Rails.application.secret_key_base, "HS256")
      end

      # Permits only specific user parameters for account creation
      def user_params
        params.require(:user).permit(:email, :password, :password_confirmation, :first_name, :last_name)
      end

      # Returns the current authenticated user
      def current_user
        @current_user ||= authenticate_request
      end
    end
  end
end
