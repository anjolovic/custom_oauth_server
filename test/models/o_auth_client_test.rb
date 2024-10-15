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
require "test_helper"

class OAuthClientTest < ActiveSupport::TestCase
  # test "the truth" do
  #   assert true
  # end
end
