class CreateAuthorizationCodes < ActiveRecord::Migration[8.0]
  def change
    create_table :authorization_codes do |t|
      t.string :code
      t.references :o_auth_client, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.string :redirect_uri
      t.datetime :expires_at
      t.string :code_challenge
      t.string :code_challenge_method
      t.json :scopes

      t.timestamps
    end
    add_index :authorization_codes, :code, unique: true
  end
end
