# frozen_string_literal: true

module LittleLanguageMistletoe
  class Routes < Hanami::Routes
    # Add your routes here. See https://guides.hanamirb.org/routing/overview/ for details.
    root to: "home.show"
    #get "/home/:id", to: "home.show"
  end
end
