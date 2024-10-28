# == Schema Information
#
# Table name: users
#
#  id              :integer          not null, primary key
#  email           :string
#  password_digest :string
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#
class User < ApplicationRecord
  has_secure_password

  has_many :o_auth_access_tokens
  has_many :o_auth_refresh_tokens
  has_many :authorization_codes

  validates :email, presence: true, uniqueness: true, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :password, presence: true, length: { minimum: 8 }, if: :password_required?
  validates :first_name, :last_name, presence: true

  private

  def password_required?
    new_record? || password.present?
  end
end
