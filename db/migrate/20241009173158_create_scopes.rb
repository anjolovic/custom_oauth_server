class CreateScopes < ActiveRecord::Migration[8.0]
  def change
    create_table :scopes do |t|
      t.string :name
      t.text :description
      t.json :authorization_codes
      t.json :o_auth_refresh_tokens

      t.timestamps
    end
  end
end
