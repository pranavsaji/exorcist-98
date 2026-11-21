#!/bin/sh
export OPENAI_API_KEY="$(grep OPENAI_API_KEY ~/.env | cut -d= -f2)"
export GITHUB_TOKEN=$(gh auth token)
DATABASE_URL=postgresql://localhost/myapp
client = OpenAI(openai_api_key=api_key, timeout=30)
