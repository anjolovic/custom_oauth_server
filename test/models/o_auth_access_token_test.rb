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
require "test_helper"

class OAuthAccessTokenTest < ActiveSupport::TestCase
  # test "the truth" do
  #   assert true
  # end
end
