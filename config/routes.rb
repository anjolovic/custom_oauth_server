Rails.application.routes.draw do
  namespace :api do
    namespace :v1 do
      get 'oauth/authorize', to: 'oauth#authorize'
      post 'oauth/token', to: 'oauth#token'
      post 'oauth/revoke', to: 'oauth#revoke'
      get 'oauth/login', to: 'oauth#login'
      get 'oauth/create_account', to: 'oauth#create_account'
      get 'oauth/user_info', to: 'oauth#user_info'
      post 'oauth/logout', to: 'oauth#logout'
    end
  end
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
