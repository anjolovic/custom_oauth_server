module ErrorHandler
    extend ActiveSupport::Concern

    included do
      rescue_from StandardError do |e|
        render json: { error: "Internal Server Error" }, status: :internal_server_error
      end

      rescue_from ActiveRecord::RecordNotFound do |e|
        render json: { error: "Resource not found" }, status: :not_found
      end

      rescue_from ActiveRecord::RecordInvalid do |e|
        render json: { errors: e.record.errors.full_messages }, status: :unprocessable_entity
      end
    end
end
