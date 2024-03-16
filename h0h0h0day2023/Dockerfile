FROM ruby:3.2.2-slim-bookworm

RUN useradd --uid 1001 --shell /bin/bash rby

COPY flag /flag
COPY . /little_language_mistletoe
WORKDIR /little_language_mistletoe
RUN apt update && apt install -y build-essential && bundle install

ENV HANAMI_ENV=production
USER 1001
EXPOSE 2311
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"] 
