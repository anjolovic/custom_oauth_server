class UserService
  Result = Struct.new(:success?, :token, :errors)

  def self.create(params)
    new(params).create
  end

  def initialize(params)
    @params = params
  end

  def create
    user = User.new(@params)
    if user.save
      token = generate_jwt(user, ["read", "write"])
      Result.new(true, token, nil)
    else
      Result.new(false, nil, user.errors.full_messages)
    end
  end

  private

  def generate_jwt(user, scopes)
    payload = {
      sub: user.id,
      scopes: scopes,
      exp: 1.hour.from_now.to_i
    }
    JWT.encode(payload, Rails.application.secret_key_base, "HS256")
  end
end
