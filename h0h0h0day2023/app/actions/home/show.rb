# frozen_string_literal: true
require 'faraday'

module LittleLanguageMistletoe
  module Actions
    module Home
      class Show < LittleLanguageMistletoe::Action
        class MyApi
          def initialize
            @conn = ::Faraday.new(url: "http://llm:3111/")
          end
          def call_llm(prompt)
            @conn.post("/", prompt.strip).body.force_encoding("UTF-8")
          end
        end

        def handle(request, response)
          method = request.GET["method"]
          arg = request.GET["argument"]

          ans = ""
          q = ""
          if method != nil and arg != nil
            q = arg
            api = MyApi.new
            begin
              ans = api.public_send(method, arg)
            rescue
            end
          end

          response.render view, answer: ans.strip, question: q.strip
        end
      end
    end
  end
end
