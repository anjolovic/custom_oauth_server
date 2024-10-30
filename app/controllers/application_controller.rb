class ApplicationController < ActionController::Base
  include ActionController::Cookies
  include ErrorHandler
  
  # Define the callback first
  before_action :verify_authenticity_token
  protect_from_forgery with: :exception
  skip_before_action :verify_authenticity_token, if: :json_request?

  private

  def json_request?
    request.format.json? || request.headers['Accept']&.include?('application/json')
  end
end
