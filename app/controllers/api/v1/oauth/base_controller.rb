module Api
  module V1
    module Oauth
      class BaseController < ApplicationController
        include ActionController::Cookies
        include ActionController::RequestForgeryProtection
        include ErrorHandler
        
        # Skip the callback after it's defined in ApplicationController
        skip_before_action :verify_authenticity_token
        protect_from_forgery with: :null_session
        before_action :authenticate_request

        private

        def current_user
          @current_user ||= authenticate_request
        end

        def authenticate_request
          token = request.headers['Authorization']&.split(' ')&.last
          @current_user = AuthenticationService.authenticate_request(token)
        end
      end
    end
  end
end
