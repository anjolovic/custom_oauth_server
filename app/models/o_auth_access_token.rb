# == Schema Information
#
# Table name: o_auth_access_tokens
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
class OAuthAccessToken < ApplicationRecord
  belongs_to :user
  belongs_to :o_auth_client

  before_create :set_expiration

  def expired?
    expires_at < Time.current
  end

  def expires_in
    (expires_at - Time.current).to_i
  end

  def revoke!
    update!(revoked_at: Time.current)
  end

  def revoked?
    revoked_at.present?
  end

  private

  def set_expiration
    self.expires_at = 1.hour.from_now
  end
end
