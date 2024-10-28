module Api
  module V1
    module Oauth
      class UsersController < ApplicationController
        def create # formerly 'create_account' action
          result = UserService.create(user_params)

          if result.success?
            render json: { token: result.token }, status: :created
          else
            render json: { errors: result.errors }, status: :unprocessable_entity
          end
        end

        def show # formerly 'user_info' action
          user = authenticate_request
          
          if user
            render json: UserSerializer.new(user).as_json  # Consistent formatting
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
