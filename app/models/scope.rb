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
class Scope < ApplicationRecord
  validates :name, presence: true, uniqueness: true
  validates :description, presence: true

  has_and_belongs_to_many :authorization_codes
  has_and_belongs_to_many :o_auth_refresh_tokens
  has_and_belongs_to_many :o_auth_access_tokens

  def self.validate_scopes(requested_scopes)
    requested_scopes.all? { |scope| exists?(name: scope) }
  end

  def self.find_scopes(scope_names)
    where(name: scope_names)
  end
end
