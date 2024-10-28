Rails.application.routes.draw do
  namespace :api do
    namespace :v1 do
      namespace :oauth do
        resource :authorization, only: [:create] do
          collection do
            get :authorize, action: :new  # Changed this line
          end
        end
        resources :tokens, only: [:create] do
          collection do
            post :revoke
          end
        end
        resource :session, only: [:create] do
          collection do
            delete :destroy, as: 'destroy'
          end
        end
        resources :users, only: [:create, :show]
      end
    end
  end

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
