class CreateOAuthRefreshTokens < ActiveRecord::Migration[8.0]
  def change
    create_table :o_auth_refresh_tokens do |t|
      t.string :token
      t.datetime :expires_at
      t.json :scopes
      t.references :o_auth_client, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.datetime :revoked_at

      t.timestamps
    end
  end
end
