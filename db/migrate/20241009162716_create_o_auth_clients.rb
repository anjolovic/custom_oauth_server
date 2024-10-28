class CreateOAuthClients < ActiveRecord::Migration[8.0]
  def change
    create_table :o_auth_clients do |t|
      t.string :name
      t.string :client_id
      t.string :client_secret_digest
      t.string :redirect_uri

      t.timestamps
    end
    add_index :o_auth_clients, :client_id, unique: true
  end
end
