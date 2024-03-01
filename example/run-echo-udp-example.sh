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
  #CLIENT_BIN_ARGS="--script-file '${EXAMPLE_DIR}/cmdscript-echo-udp.txt' --verbose"
  CLIENT_BIN_ARGS="--verbose"
else
  #GATEWAY_BIN_ARGS="--no-mask-addrs --mfa-scheme scram-sha256"
  GATEWAY_BIN_ARGS="--no-mask-addrs"
  #CLIENT_BIN_ARGS="--script-file '${EXAMPLE_DIR}/cmdscript-echo-udp.txt'"
  CLIENT_BIN_ARGS=""
fi

source "${EXAMPLE_DIR}"/target/example.conf

PS1='$ ' "${TMUX_CMD}" new-session -s trust0-echo-udp-example \; \
  set -g mouse on \; \
  send-keys '(clear && read -p "Step 1: Hit <Enter> to run trust0 gateway" && "'"${GMAKE_CMD}"'" run-trust0-gateway-nodeps EXECBIN_EXTRA_ARGS="'"${GATEWAY_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 65% \; \
  send-keys '(clear && echo "Step 2.1: Hit <Enter> to run trust0 client (after gateway is up)" && read -p "Step 2.2: Enter \"start -s echo-udp -p '"${ECHO_PROXY__PORT}"'\" (to start service proxy)" && "'"${GMAKE_CMD}"'" run-trust0-client-nodeps EXECBIN_EXTRA_ARGS="'"${CLIENT_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 43% \; \
  send-keys '(clear && read -p "Step 3: Hit <Enter> to run echo server" && "'"${NCAT_CMD}"'" -v -u -k -l -p '"${ECHO_SERVICE__PORT}"' --exec "'"${CAT_CMD}"'")' C-m \; \
  split-window -h -l 65% \; \
  send-keys '(clear && read -p "Step 4: Hit <Enter> to run echo client (after service proxy has started)" && "'"${NCAT_CMD}"'" -v -u 127.0.0.1 '"${ECHO_PROXY__PORT}"')' C-m \; \
  split-window -h -l 38% \; \
  send-keys '(clear && read -p "Step Last: Hit <Enter> to shutdown example" && ("'"${TMUX_CMD}"'" kill-session -t trust0-echo-udp-example))' C-m \; \
  select-pane -t 0 \;

