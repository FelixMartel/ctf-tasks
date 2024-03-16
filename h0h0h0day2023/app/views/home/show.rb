# frozen_string_literal: true

module LittleLanguageMistletoe
  module Views
    module Home
      class Show < LittleLanguageMistletoe::View
        expose :answer, :question
      end
    end
  end
end
