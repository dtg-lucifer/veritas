#!/usr/bin/env bash
set -e

echo "🐳 Starting Redis Container & Backend Test Suite..."
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner

echo "🧹 Cleaning up test containers..."
docker compose -f docker-compose.test.yml down -v

echo "🎉 All Docker tests passed successfully!"
