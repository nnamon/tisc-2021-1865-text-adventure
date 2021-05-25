Rails.application.routes.draw do
  root 'welcome#index'

  get "/api/v1/smoke", to: "smoke#remember"
  # For details on the DSL available within this file, see https://guides.rubyonrails.org/routing.html
end
