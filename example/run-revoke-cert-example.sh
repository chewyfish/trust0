#!/usr/bin/env bash

set -euo pipefail

EXAMPLE_DIR=$(dirname "$0")
EXAMPLE_BUILD_DIR="${EXAMPLE_DIR}/target"
NCAT_CMD=ncat
TMUX_CMD=tmux

# Build binaries/pki/db/...

"${EXAMPLE_DIR}"/run-configure.sh
make clean-all
make gateway-server-pki
make client-pki
make setup-crl-files
make trust0-gateway
make trust0-client

# Run example in tmux session

CLIENT_REVOKED_CRLFILE="${EXAMPLE_BUILD_DIR}/revoked-example-client.local.crl.pem"
GATEWAY_CONFIGURED_CRLFILE="${EXAMPLE_BUILD_DIR}/revoked.crl.pem"

ARG1=${1:-}
if [ "$ARG1" == "verbose" ]; then
  GATEWAY_BIN_ARGS="--crl-file '${GATEWAY_CONFIGURED_CRLFILE}' --verbose --no-mask-addrs"
  CLIENT_BIN_ARGS="--verbose"
else
  GATEWAY_BIN_ARGS="--crl-file '${GATEWAY_CONFIGURED_CRLFILE}' --no-mask-addrs"
  CLIENT_BIN_ARGS=""
fi

source "${EXAMPLE_DIR}/target/example.conf"

PS1='$ ' ${TMUX_CMD} new-session -s trust0-echo-udp-example \; \
  set -g mouse on \; \
  send-keys '(clear && read -p "Step 1: Hit <Enter> to run trust0 gateway" && make run-trust0-gateway-nodeps EXECBIN_EXTRA_ARGS="'"${GATEWAY_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 65% \; \
  send-keys '(clear && echo "Step 2.1: Hit <Enter> to run trust0 client (after gateway is up)" && read -p "Step 2.2: Enter \"start -s echo-udp -p '"${ECHO_PROXY__PORT}"'\" (to start service proxy)" && make run-trust0-client-nodeps EXECBIN_EXTRA_ARGS="'"${CLIENT_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 43% \; \
  send-keys '(clear && read -p "Step 3: Hit <Enter> to run echo server" && '"${NCAT_CMD}"' -v -u -k -l -p '"${ECHO_SERVICE__PORT}"' --exec "/bin/cat")' C-m \; \
  split-window -h -l 74% \; \
  send-keys '(clear && read -p "Step 4: Hit <Enter> to run echo client (after service proxy has started)" && '"${NCAT_CMD}"' -v -u localhost '"${ECHO_PROXY__PORT}"')' C-m \; \
  split-window -h -l 62% \; \
  send-keys '(clear && echo "Step 5: Hit <Enter> to run echo client (after service proxy has started)" && read -p "(Will delay 35s so that CRL can be reloaded)" && cp '"${CLIENT_REVOKED_CRLFILE}"' '"${GATEWAY_CONFIGURED_CRLFILE}"' && sleep 35 && '"${NCAT_CMD}"' -v -u localhost '"${ECHO_PROXY__PORT}"')' C-m \; \
  split-window -h -l 38% \; \
  send-keys '(clear && read -p "Step Last: Hit <Enter> to shutdown example" && ('"${TMUX_CMD}"' kill-session -t trust0-echo-udp-example))' C-m \; \
  select-pane -t 0 \;

