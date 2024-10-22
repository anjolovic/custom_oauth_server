module OAuth
  class Error < StandardError
    attr_reader :status

    def initialize(message, status = :bad_request)
      super(message)
      @status = status
    end
  end
end