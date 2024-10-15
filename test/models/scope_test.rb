# == Schema Information
#
# Table name: scopes
#
#  id                    :integer          not null, primary key
#  name                  :string
#  description           :text
#  authorization_codes   :json
#  o_auth_refresh_tokens :json
#  created_at            :datetime         not null
#  updated_at            :datetime         not null
#
