#!/bin/sh
# Seed OpenAI key so the gateway can forward OpenClaw traffic. Only OPENAI_API_KEY is used.
if [ -n "$OPENAI_API_KEY" ]; then
  talon secrets set openai-api-key "$OPENAI_API_KEY" 2>/dev/null || true
fi
# Agent traffic key (#266): the key OpenClaw presents as Bearer.
if ! talon secrets list 2>/dev/null | grep -q openclaw-main-talon-key; then
  talon secrets set openclaw-main-talon-key "${TALON_AGENT_KEY:-talon-gw-openclaw-001}" 2>/dev/null || true
fi
GATEWAY_CONFIG="${GATEWAY_CONFIG_PATH:-/etc/talon/gateway/talon.config.gateway.yaml}"
exec talon serve --gateway --gateway-config="$GATEWAY_CONFIG" --port "${PORT:-8080}"
