module Api
  module V1
    module Oauth
      class UsersController < BaseController
        skip_before_action :authenticate_request, only: [:create]
        
        def create
          result = UserService.create(
            user_params.merge(client_id: params[:client_id])
          )

          if result.success?
            response.headers['Authorization'] = "Bearer #{result.token}"
            
            render json: {
              token: result.token,
              user: UserSerializer.new(result.user).as_json,
              redirect_to: params[:return_to]
            }, status: :created
          else
            render json: { errors: result.errors }, status: :unprocessable_entity
          end
        end

        def show
          user = authenticate_request
          
          if user
            render json: UserSerializer.new(user).as_json
          else
            render json: { error: "Unauthorized" }, status: :unauthorized
          end
        end

        private

        def user_params
          params.require(:user).permit(:email, :password, :password_confirmation, :first_name, :last_name)
        end
      end
    end
  end
end
