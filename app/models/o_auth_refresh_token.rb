# == Schema Information
#
# Table name: o_auth_refresh_tokens
#
#  id               :integer          not null, primary key
#  token            :string
#  expires_at       :datetime
#  scopes           :json
#  o_auth_client_id :integer          not null
#  user_id          :integer          not null
#  revoked_at       :datetime
#  created_at       :datetime         not null
#  updated_at       :datetime         not null
#
class OAuthRefreshToken < ApplicationRecord
  belongs_to :o_auth_client, class_name: 'OAuthClient'
  belongs_to :user

  before_create :set_expiration

  def expired?
    expires_at < Time.current
  end

  def revoke!
    update!(revoked_at: Time.current)
  end

  def revoked?
    revoked_at.present?
  end

  private

  def set_expiration
    self.expires_at = 30.days.from_now
  end
end
