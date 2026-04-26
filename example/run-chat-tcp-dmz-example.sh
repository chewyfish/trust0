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

PS1='$ ' "${TMUX_CMD}" new-session -s trust0-chat-tcp-example \; \
  set -g mouse on \; \
  send-keys '(clear && read -p "Step 1: Hit <Enter> to run chat server (or prior to executing chat client)" && "'"${NCAT_CMD}"'" -v -k -l -p '"${CHAT_SERVICE__PORT}"' --chat)' C-m \; \
  split-window -v -l 85% \; \
  send-keys '(clear && read -p "Step 2: Hit <Enter> to run trust0 (service) gateway" && "'"${GMAKE_CMD}"'" run-trust0-dmz-service-gateway-nodeps EXECBIN_EXTRA_ARGS="'"${GATEWAY_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 75% \; \
  send-keys '(clear && read -p "Step 3: Hit <Enter> to run trust0 (client) gateway" && "'"${GMAKE_CMD}"'" run-trust0-dmz-client-gateway-nodeps EXECBIN_EXTRA_ARGS="'"${GATEWAY_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 65% \; \
  send-keys '(clear && echo "Step 4.1: Hit <Enter> to run trust0 client (after gateway is up)" && read -p "Step 4.2: Enter \"start -s chat-tcp -p '"${CHAT_PROXY__PORT}"'\" (to start service proxy)" && "'"${GMAKE_CMD}"'" run-trust0-client-nodeps EXECBIN_EXTRA_ARGS="'"${CLIENT_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 45% \; \
  send-keys '(clear && read -p "Step 5: Hit <Enter> to run 1st chat client (after service proxy has started)" && "'"${NCAT_CMD}"'" -v 127.0.0.1 '"${CHAT_PROXY__PORT}"')' C-m \; \
  split-window -h -l 50% \; \
  send-keys '(clear && echo "Step 6.1: Hit <Enter> to run 2nd chat client (after service proxy has started)" && read -p "Step 6.2: Enter chat messages between chat clients" && "'"${NCAT_CMD}"'" -v 127.0.0.1 '"${CHAT_PROXY__PORT}"')' C-m \; \
  select-pane -t 0 \; \
  split-window -h -l 25% \; \
  send-keys '(clear && read -p "Step Last: Hit <Enter> to shutdown example" && ("'"${TMUX_CMD}"'" kill-session -t trust0-chat-tcp-example))' C-m \; \
  select-pane -t 0 \;

