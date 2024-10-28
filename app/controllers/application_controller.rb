class ApplicationController < ActionController::Base
  include ActionController::Cookies
  include ErrorHandler
  
  # Define the callback first
  before_action :verify_authenticity_token
  protect_from_forgery with: :exception
end
