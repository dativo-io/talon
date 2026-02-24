#!/bin/sh
# Seed gateway provider secrets from env if set (so OpenClaw traffic can be forwarded).
if [ -n "$OPENAI_API_KEY" ]; then
  talon secrets set openai-api-key "$OPENAI_API_KEY" 2>/dev/null || true
fi
if [ -n "$ANTHROPIC_API_KEY" ]; then
  talon secrets set anthropic-api-key "$ANTHROPIC_API_KEY" 2>/dev/null || true
fi
GATEWAY_CONFIG="${GATEWAY_CONFIG_PATH:-/etc/talon/gateway/talon.config.gateway.yaml}"
exec talon serve --gateway --gateway-config="$GATEWAY_CONFIG" --port "${PORT:-8080}"
