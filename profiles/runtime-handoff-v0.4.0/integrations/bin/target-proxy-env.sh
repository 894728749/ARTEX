#!/usr/bin/env bash
# Source after proxy-env.sh: infrastructure keeps the existing Windows gateway.
export ARTEX_LLM_PROXY="$HTTPS_PROXY"
export ARTEX_TARGET_PROXY="$ARTEX_LLM_PROXY"
if [ -f "$ARTEX_INTEGRATIONS_ROOT/tor/enabled" ]; then
  export ARTEX_TARGET_PROXY='http://127.0.0.1:18118'
  export HTTP_PROXY="$ARTEX_TARGET_PROXY" HTTPS_PROXY="$ARTEX_TARGET_PROXY" ALL_PROXY="$ARTEX_TARGET_PROXY"
  export http_proxy="$ARTEX_TARGET_PROXY" https_proxy="$ARTEX_TARGET_PROXY" all_proxy="$ARTEX_TARGET_PROXY"
fi
