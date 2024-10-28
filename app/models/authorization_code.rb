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
  belongs_to :user
  belongs_to :o_auth_client

  validates :code, presence: true
  validates :redirect_uri, presence: true
  validates :expires_at, presence: true
  validates :code_challenge, presence: true, if: :pkce_required?
  validates :code_challenge_method, presence: true, if: :pkce_required?

  def expired?
    expires_at < Time.current
  end

  private

  def pkce_required?
    code_challenge.present? || code_challenge_method.present?
  end
end
