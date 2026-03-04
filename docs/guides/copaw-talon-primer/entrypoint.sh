#!/bin/sh
# Seed OpenAI key so the gateway can forward CoPaw traffic.
if [ -n "$OPENAI_API_KEY" ]; then
  talon secrets set openai-api-key "$OPENAI_API_KEY" 2>/dev/null || true
fi
GATEWAY_CONFIG="${GATEWAY_CONFIG_PATH:-/etc/talon/gateway/talon.config.gateway.yaml}"
exec talon serve --gateway --gateway-config="$GATEWAY_CONFIG" --port "${PORT:-8080}"
