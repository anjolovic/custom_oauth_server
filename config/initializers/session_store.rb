Rails.application.config.session_store :cookie_store, 
  key: '_oauth_server_session',
  secure: Rails.env.production?,
  expire_after: 30.days
