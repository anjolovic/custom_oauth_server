module ErrorHandler
    extend ActiveSupport::Concern
  
    included do
      rescue_from StandardError, with: :internal_server_error
      rescue_from ActiveRecord::RecordNotFound, with: :not_found
      rescue_from ActionController::ParameterMissing, with: :bad_request
      rescue_from OAuth::Error, with: :oauth_error
    end
  
    private
  
    def internal_server_error(exception)
      log_error(exception)
      render json: { error: 'Internal Server Error' }, status: :internal_server_error
    end
  
    def not_found(exception)
      log_error(exception)
      render json: { error: 'Not Found' }, status: :not_found
    end
  
    def bad_request(exception)
      log_error(exception)
      render json: { error: exception.message }, status: :bad_request
    end
  
    def oauth_error(exception)
      log_error(exception)
      render json: { error: exception.message }, status: exception.status
    end
  
    def log_error(exception)
      Rails.logger.error "#{exception.class}: #{exception.message}"
      Rails.logger.error exception.backtrace.join("\n")
    end
  end