module Api
  module V1
    module Oauth
      class SessionsController < BaseController
        skip_before_action :authenticate_request, only: [:create]

        def create
          result = SessionService.create(
            email: params[:email],
            password: params[:password]
          )

          if result.success?
            store_oauth_params if params[:client_id].present?
            
            render json: { 
              token: result.token,
              redirect_to: params[:return_to]
            }
          else
            render json: { error: result.error }, status: :unauthorized
          end
        end

        def destroy
          result = SessionService.destroy(
            token: request.headers["Authorization"]&.split(" ")&.last
          )

          if result.success?
            render json: { message: "Logged out successfully" }
          else
            render json: { error: result.error }, status: result.status
          end
        end

        private

        def store_oauth_params
          session[:oauth_params] = {
            client_id: params[:client_id],
            redirect_uri: params[:redirect_uri],
            code_challenge: params[:code_challenge],
            code_challenge_method: params[:code_challenge_method],
            scope: params[:scope],
            state: params[:state]
          }
        end
      end
    end
  end
end
