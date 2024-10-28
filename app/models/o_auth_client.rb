# == Schema Information
#
# Table name: o_auth_clients
#
#  id                  :integer          not null, primary key
#  name                :string
#  client_id           :string
#  client_secret_digest :string
#  redirect_uri        :string
#  created_at          :datetime         not null
#  updated_at          :datetime         not null
#
class OAuthClient < ApplicationRecord
  has_many :o_auth_access_tokens
  has_many :o_auth_refresh_tokens

  has_secure_password :client_secret

  validates :name, :client_id, :redirect_uri, presence: true
  validates :client_id, uniqueness: true

  before_validation :generate_credentials, on: :create

  # Add this method to handle client authentication
  def authenticate(secret)
    authenticate_client_secret(secret)
  end

  private

  def generate_credentials
    self.client_id ||= SecureRandom.hex(16)
    self.client_secret ||= SecureRandom.hex(32)
  end
end
