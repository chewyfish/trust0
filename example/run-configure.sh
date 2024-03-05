#!/usr/bin/env bash

set -euo pipefail

cd $(dirname "$0")

EXAMPLE_DIR=$(pwd)
EXAMPLE_BUILD_DIR="${EXAMPLE_DIR}/target"
EXAMPLE_CONFIG_FILE="${EXAMPLE_BUILD_DIR}/example.conf"

DATASOURCE_INMEMDB_ACCESS_M4_FILE="${EXAMPLE_DIR}/trust0-db-access.json.m4"
DATASOURCE_INMEMDB_ACCESS_FILE="${EXAMPLE_BUILD_DIR}/trust0-db-access.json"
DATASOURCE_INMEMDB_SERVICE_M4_FILE="${EXAMPLE_DIR}/trust0-db-service.json.m4"
DATASOURCE_INMEMDB_SERVICE_FILE="${EXAMPLE_BUILD_DIR}/trust0-db-service.json"
DATASOURCE_INMEMDB_ROLE_M4_FILE="${EXAMPLE_DIR}/trust0-db-role.json.m4"
DATASOURCE_INMEMDB_ROLE_FILE="${EXAMPLE_BUILD_DIR}/trust0-db-role.json"
DATASOURCE_INMEMDB_USER_M4_FILE="${EXAMPLE_DIR}/trust0-db-user.json.m4"
DATASOURCE_INMEMDB_USER_FILE="${EXAMPLE_BUILD_DIR}/trust0-db-user.json"

DATE_CMD=${DATE_CMD:-date}
GMAKE_CMD=${GMAKE_CMD:-gmake}
CARGO_CMD=${CARGO_CMD:-cargo}
DOCKER_CMD=${DOCKER_CMD:-docker222}
DOCKER_COMPOSE_CMD=${DOCKER_COMPOSE_CMD:-docker-compose}
OPENSSL_CMD=${OPENSSL_CMD:-openssl}
M4_CMD=${M4_CMD:-m4}
TMUX_CMD=${TMUX_CMD:-tmux}
NCAT_CMD=${NCAT_CMD:-ncat}
CAT_CMD=${CAT_CMD:-cat}

# Check pre-requisites

PREREQ_MISSING=0

if ((BASH_VERSINFO[0] < 4)); then
  echo "Bash version 4 or higher required"
  PREREQ_MISSING=1
fi

function check_command_exists() {
  local command="$1"
  local required="$2"
  if ! which "${command}" 2> /dev/null > /dev/null; then
    if [ "${required}" == "Y" ]; then
      echo "Command '${command}' missing, please install"
      PREREQ_MISSING=1
    else
      echo "Command '${command}' missing, please install (if needed)"
    fi
    return 1
  fi
  return 0
}

check_command_exists "${DATE_CMD}" "Y" && DATE_CMD=$(which "${DATE_CMD}")
check_command_exists "${GMAKE_CMD}" "Y" && GMAKE_CMD=$(which "${GMAKE_CMD}")
check_command_exists "${CARGO_CMD}" "Y" && CARGO_CMD=$(which "${CARGO_CMD}")
check_command_exists "${DOCKER_CMD}" "N" && DOCKER_CMD=$(which "${DOCKER_CMD}")
check_command_exists "${DOCKER_COMPOSE_CMD}" "N" && DOCKER_COMPOSE_CMD=$(which "${DOCKER_COMPOSE_CMD}")
check_command_exists "${OPENSSL_CMD}" "N" && OPENSSL_CMD=$(which "${OPENSSL_CMD}")
check_command_exists "${M4_CMD}" "Y" && M4_CMD=$(which "${M4_CMD}")
check_command_exists "${TMUX_CMD}" "Y" && TMUX_CMD=$(which "${TMUX_CMD}")
check_command_exists "${NCAT_CMD}" "Y" && NCAT_CMD=$(which "${NCAT_CMD}")
check_command_exists "${CAT_CMD}" "Y" && CAT_CMD=$(which "${CAT_CMD}")

if [ "${PREREQ_MISSING}" == "1" ]; then
  exit 1
fi

# Check if configuration is needed

RECONFIGURE=n
if [ -f "${EXAMPLE_CONFIG_FILE}" ]; then
  read -p "Example config file already exists, enter 'y' to reconfigure this file: " reconf_config
  if [ "$reconf_config" == 'y' ]; then
    RECONFIGURE=y
  fi
else
  RECONFIGURE=y
fi

read -p "If example requires secondary authentication credentials, please use \"user1\", \"pass1\""

# Create core application configuration files

if [ "$RECONFIGURE" == 'y' ]; then
  mkdir -p "${EXAMPLE_BUILD_DIR}"
  rm -f "${EXAMPLE_CONFIG_FILE}" "${DATASOURCE_INMEMDB_ACCESS_FILE}" "${DATASOURCE_INMEMDB_SERVICE_FILE}" "${DATASOURCE_INMEMDB_ROLE_FILE}" "${DATASOURCE_INMEMDB_USER_FILE}"
  read -rp "Enter an available port for the trust0 gateway: " gateway_port && echo TRUST0_GATEWAY__PORT=${gateway_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the chat service: " chat_service_port && echo CHAT_SERVICE__PORT=${chat_service_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the chat proxy: " chat_proxy_port && echo CHAT_PROXY__PORT=${chat_proxy_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the echo service: " echo_service_port && echo ECHO_SERVICE__PORT=${echo_service_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the echo proxy: " echo_proxy_port && echo ECHO_PROXY__PORT=${echo_proxy_port} >> ${EXAMPLE_CONFIG_FILE}
fi

if [ ! -f "${DATASOURCE_INMEMDB_ACCESS_FILE}" ] ||  [ ! -f "${DATASOURCE_INMEMDB_SERVICE_FILE}" ] ||  [ ! -f "${DATASOURCE_INMEMDB_ROLE_FILE}" ] ||  [ ! -f "${DATASOURCE_INMEMDB_USER_FILE}" ]; then
  source "${EXAMPLE_CONFIG_FILE}"
  ${M4_CMD} "${DATASOURCE_INMEMDB_ACCESS_M4_FILE}" > "${DATASOURCE_INMEMDB_ACCESS_FILE}"
  ${M4_CMD} -D xCHAT_PORT="${CHAT_SERVICE__PORT}" -D xECHO_PORT="${ECHO_SERVICE__PORT}" "${DATASOURCE_INMEMDB_SERVICE_M4_FILE}" > "${DATASOURCE_INMEMDB_SERVICE_FILE}"
  ${M4_CMD} "${DATASOURCE_INMEMDB_ROLE_M4_FILE}" > "${DATASOURCE_INMEMDB_ROLE_FILE}"
  ${M4_CMD} "${DATASOURCE_INMEMDB_USER_M4_FILE}" > "${DATASOURCE_INMEMDB_USER_FILE}"
fi
