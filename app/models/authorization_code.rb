# == Schema Information
#
# Table name: authorization_codes
#
#  id                    :integer          not null, primary key
#  code                  :string
#  o_auth_client_id      :integer          not null
#  user_id               :integer          not null
#  redirect_uri          :string
#  expires_at            :datetime
#  code_challenge        :string
#  code_challenge_method :string
#  scopes                :json
#  created_at            :datetime         not null
#  updated_at            :datetime         not null
#
class AuthorizationCode < ApplicationRecord
  belongs_to :o_auth_client  # The client application that requested the authorization
  belongs_to :user          # The user who granted the authorization

  validates :code, presence: true, uniqueness: true
  validates :redirect_uri, :expires_at, :code_challenge, :code_challenge_method, presence: true

  def expired?
    expires_at < Time.current
  end
end
