# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.0].define(version: 2024_10_10_160100) do
  create_table "authorization_codes", force: :cascade do |t|
    t.string "code"
    t.integer "o_auth_client_id", null: false
    t.integer "user_id", null: false
    t.string "redirect_uri"
    t.datetime "expires_at"
    t.string "code_challenge"
    t.string "code_challenge_method"
    t.json "scopes"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["code"], name: "index_authorization_codes_on_code", unique: true
    t.index ["o_auth_client_id"], name: "index_authorization_codes_on_o_auth_client_id"
    t.index ["user_id"], name: "index_authorization_codes_on_user_id"
  end

  create_table "o_auth_access_tokens", force: :cascade do |t|
    t.string "token"
    t.datetime "expires_at"
    t.json "scopes"
    t.integer "o_auth_client_id", null: false
    t.integer "user_id", null: false
    t.datetime "revoked_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["o_auth_client_id"], name: "index_o_auth_access_tokens_on_o_auth_client_id"
    t.index ["user_id"], name: "index_o_auth_access_tokens_on_user_id"
  end

  create_table "o_auth_clients", force: :cascade do |t|
    t.string "name"
    t.string "client_id"
    t.string "client_secret"
    t.string "redirect_uri"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["client_id"], name: "index_o_auth_clients_on_client_id", unique: true
  end

  create_table "o_auth_refresh_tokens", force: :cascade do |t|
    t.string "token"
    t.datetime "expires_at"
    t.json "scopes"
    t.integer "o_auth_client_id", null: false
    t.integer "user_id", null: false
    t.datetime "revoked_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["o_auth_client_id"], name: "index_o_auth_refresh_tokens_on_o_auth_client_id"
    t.index ["user_id"], name: "index_o_auth_refresh_tokens_on_user_id"
  end

  create_table "scopes", force: :cascade do |t|
    t.string "name"
    t.text "description"
    t.json "authorization_codes"
    t.json "o_auth_refresh_tokens"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "users", force: :cascade do |t|
    t.string "email"
    t.string "password_digest"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  add_foreign_key "authorization_codes", "o_auth_clients"
  add_foreign_key "authorization_codes", "users"
  add_foreign_key "o_auth_access_tokens", "o_auth_clients"
  add_foreign_key "o_auth_access_tokens", "users"
  add_foreign_key "o_auth_refresh_tokens", "o_auth_clients"
  add_foreign_key "o_auth_refresh_tokens", "users"
end
