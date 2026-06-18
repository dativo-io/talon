#!/usr/bin/env bash
# Shared helper: sets COMPOSE to "docker compose" or "sudo docker compose".
# Usage: source this file, then call detect_docker_compose.

detect_docker_compose() {
  if [[ -n "${COMPOSE:-}" ]]; then
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker not found. See examples/shortlist-demo/README.md#prerequisites." >&2
    exit 127
  fi
  if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
    export COMPOSE
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo docker compose version >/dev/null 2>&1; then
    COMPOSE="sudo docker compose"
    export COMPOSE
    echo "Note: using sudo for docker compose (sudo usermod -aG docker \"\$USER\" to avoid)" >&2
    return 0
  fi
  echo "Error: docker compose not available (permission denied on /var/run/docker.sock?)." >&2
  echo "Fix: sudo usermod -aG docker \"\$USER\" && newgrp docker" >&2
  exit 1
}
