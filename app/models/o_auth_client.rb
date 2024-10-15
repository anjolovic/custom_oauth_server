# == Schema Information
#
# Table name: o_auth_clients
#
#  id            :integer          not null, primary key
#  name          :string
#  client_id     :string
#  client_secret :string
#  redirect_uri  :string
#  created_at    :datetime         not null
#  updated_at    :datetime         not null
#
class OAuthClient < ApplicationRecord
  has_many :o_auth_access_tokens
  has_many :o_auth_refresh_tokens

  validates :name, :client_id, :client_secret, :redirect_uri, presence: true
  validates :client_id, uniqueness: true

  def authenticate(secret)
    client_secret == secret
  end
end
