module Api
  module V1
    module Oauth
      class AuthorizationsController < BaseController
        skip_before_action :authenticate_request, only: [:new]

        def new
          # First check client and redirect_uri validity
          client = OAuthClient.find_by(client_id: params[:client_id])
          
          if !client
            return render json: { error: "Invalid client ID: #{params[:client_id]}" }, status: :unauthorized
          end

          if params[:redirect_uri] != client.redirect_uri
            return render json: { 
              error: "Invalid redirect URI. Expected: #{client.redirect_uri}, Got: #{params[:redirect_uri]}" 
            }, status: :unauthorized
          end

          # Then check authentication
          unless current_user
            # Store the OAuth params in session
            session[:oauth_params] = {
              client_id: params[:client_id],
              redirect_uri: params[:redirect_uri],
              code_challenge: params[:code_challenge],
              code_challenge_method: params[:code_challenge_method],
              scope: params[:scope],
              state: params[:state]
            }
            
            # Return login required response
            return render json: { 
              error: "Login required",
              login_url: "/login?return_to=#{CGI.escape(request.original_url)}"
            }, status: :unauthorized
          end

          result = AuthorizationService.create(
            client_id: params[:client_id],
            redirect_uri: params[:redirect_uri],
            code_challenge: params[:code_challenge],
            code_challenge_method: params[:code_challenge_method],
            scope: params[:scope],
            current_user: current_user
          )

          if result.success?
            redirect_to "#{result.redirect_uri}?code=#{result.auth_code}&state=#{params[:state]}", allow_other_host: true
          else
            render json: { error: result.error }, status: :unauthorized
          end
        rescue StandardError => e
          render json: { error: e.message }, status: :internal_server_error
        end

        # Keep the create method for backward compatibility
        alias_method :create, :new
      end
    end
  end
end
