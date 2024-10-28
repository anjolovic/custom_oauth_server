module Api
  module V1
    module Oauth
      class TokensController < BaseController
        def create
          client = authenticate_client
          return unless client

          result = TokenService.create(
            client: client,
            grant_type: params[:grant_type],
            params: token_params
          )

          if result.success?
            response.headers['Authorization'] = "Bearer #{result.response[:access_token]}"
            render json: result.response
          else
            Rails.logger.error "Token creation failed: #{result.error}"
            render json: { error: result.error }, status: result.status || :unprocessable_entity
          end
        rescue StandardError => e
          Rails.logger.error "Token creation error: #{e.message}"
          Rails.logger.error e.backtrace.join("\n")
          render json: { error: e.message }, status: :internal_server_error
        end

        def revoke
          result = TokenService.revoke(token: params[:token])
          
          if result.success?
            head :ok
          else
            render json: { error: result.error }, status: result.status || :not_found
          end
        end

        private

        def token_params
          params.permit(
            :code, 
            :refresh_token, 
            :code_verifier, 
            :scope, 
            :grant_type, 
            :client_id, 
            :client_secret
          )
        end

        def authenticate_client
          client = OAuthClient.find_by(client_id: params[:client_id])
          if client&.authenticate(params[:client_secret])
            client
          else
            render json: { error: "Invalid client credentials" }, status: :unauthorized
            nil
          end
        end
      end
    end
  end
end
