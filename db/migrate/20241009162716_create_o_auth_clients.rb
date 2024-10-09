class CreateOAuthClients < ActiveRecord::Migration[8.0]
  def change
    create_table :o_auth_clients do |t|
      t.string :name
      t.string :client_id
      t.string :client_secret
      t.string :redirect_uri

      t.timestamps
    end
  end
end
