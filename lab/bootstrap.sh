#!/usr/bin/env sh
# Prepare the benchmark apps (database setup). Usage: ./lab/bootstrap.sh [dvwa bwapp mutillidae ...]
set -eu
cd "$(dirname "$0")/.."
exec docker compose -f docker-compose.yml -f docker-compose.lab.yml exec api python /lab/bootstrap.py "$@"
