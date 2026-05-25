#!/usr/bin/env bash

set -euo pipefail

EXAMPLE_DIR=$(dirname "$0")

# Build binaries/pki/config/db/...

source "${EXAMPLE_DIR}"/run-configure.sh
"${GMAKE_CMD}" clean-all
"${GMAKE_CMD}" trust0-gateway
"${GMAKE_CMD}" trust0-client
"${GMAKE_CMD}" root-ca-pki
"${GMAKE_CMD}" gateway-server-pki
"${GMAKE_CMD}" client-pki

# Run example in tmux session

ARG1=${1:-}
if [ "$ARG1" == "verbose" ]; then
  #GATEWAY_BIN_ARGS="--verbose --no-mask-addrs --mfa-scheme scram-sha256"
  GATEWAY_BIN_ARGS="--verbose --no-mask-addrs"
  #CLIENT_BIN_ARGS="--script-file '${EXAMPLE_DIR}/cmdscript-chat-tcp.txt' --verbose"
  CLIENT_BIN_ARGS="--verbose"
else
  #GATEWAY_BIN_ARGS="--no-mask-addrs --mfa-scheme scram-sha256"
  GATEWAY_BIN_ARGS="--no-mask-addrs"
  #CLIENT_BIN_ARGS="--script-file '${EXAMPLE_DIR}/cmdscript-chat-tcp.txt'"
  CLIENT_BIN_ARGS=""
fi

source "${EXAMPLE_DIR}"/target/example.conf

CACERT_FILE="${EXAMPLE_BUILD_DIR}/example-ca.local.crt.pem"

PS1='$ ' "${TMUX_CMD}" new-session -s trust0-web-tls-example \; \
  set -g mouse on \; \
  send-keys '(clear && read -p "Step 1.1: Ensure https://www.example.com is accessible. Step 1.2 Ensure '"${TRUST0_CLIENT__PKI_NAME}"' resolves to your trust0 client. Hit <Enter> to go to shell prompt if needed.")' C-m \; \
  split-window -v -l 80% \; \
  send-keys '(clear && read -p "Step 2: Hit <Enter> to run trust0 gateway" && "'"${GMAKE_CMD}"'" run-trust0-gateway-nodeps EXECBIN_EXTRA_ARGS="'"${GATEWAY_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 70% \; \
  send-keys '(clear && echo "Step 3.1: Hit <Enter> to run trust0 client (after gateway is up)" && read -p "Step 3.2: Enter \"start -s examplecom-tls -p '"${EXAMPLECOM_PROXY__PORT}"'\" (to start service proxy)" && "'"${GMAKE_CMD}"'" run-trust0-client-nodeps EXECBIN_EXTRA_ARGS="'"${CLIENT_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 60% \; \
  send-keys '(clear && read -p "Step 4: Hit <Enter> to run curl request" && echo "\"'"${CURL_CMD}"'\" -vv --proxytunnel --proxy-cacert \"'"${CACERT_FILE}"'\" -x https://'"${TRUST0_CLIENT__PKI_NAME}"':'"${EXAMPLECOM_PROXY__PORT}"' http://www.example.com:443 " && "'"${CURL_CMD}"'" -vv --proxytunnel --proxy-cacert "'"${CACERT_FILE}"'" -x https://'"${TRUST0_CLIENT__PKI_NAME}"':'"${EXAMPLECOM_PROXY__PORT}"' http://www.example.com:443/ )' C-m \; \
  select-pane -t 0 \; \
  split-window -h -l 25% \; \
  send-keys '(clear && read -p "Step Last: Hit <Enter> to shutdown example" && ("'"${TMUX_CMD}"'" kill-session -t trust0-web-tls-example))' C-m \; \
  select-pane -t 0 \;

