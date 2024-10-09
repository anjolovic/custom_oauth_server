class OAuthRefreshToken < ApplicationRecord
  belongs_to :oauth_client
  belongs_to :user
end
