#!/usr/bin/env bash

set -euo pipefail

if ((BASH_VERSINFO[0] < 4)); then
  echo "Bash version 4 or higher required" >&2
  exit 1
fi

cd "$(dirname "$0")"
PWD=$(pwd)
printf -v RUNKEY '%(%s)T' -1

declare -r PERFTEST_DIR="${PWD}"
declare -r PERFTEST_BUILD_DIR="${PERFTEST_DIR}/target/${RUNKEY}"
declare -r PERFTEST_DOCKER_COMPOSE_FILE="${PERFTEST_BUILD_DIR}/docker-compose.yml"

declare -r DOCKER_COMPOSE_ALL_M4_FILE="${PERFTEST_DIR}/docker-compose-all.yml.m4"
declare -r DOCKER_COMPOSE_TCP_M4_FILE="${PERFTEST_DIR}/docker-compose-tcp.yml.m4"
declare -r DOCKER_COMPOSE_UDP_M4_FILE="${PERFTEST_DIR}/docker-compose-udp.yml.m4"
declare -r TRANSPORT_ALL="ALL"
declare -r TRANSPORT_TCP="tcp"
declare -r TRANSPORT_UDP="udp"
declare -r TRANSPORT_PATTERN="^(${TRANSPORT_ALL}|${TRANSPORT_TCP}|${TRANSPORT_UDP})$";
declare -r QPS_PER_TRANSPORT_PATTERN='^[0-9]+$';
declare -r CONNECTIONS_PER_TRANSPORT_PATTERN='^[0-9]+$';
declare -r MAX_EXECUTION_TIME_MIN_PATTERN='^[0-9]+$';

declare -r TRUST0_GATEWAY1__CONFIG_FILE=t0perf-t0gateway1.rc
declare -r TRUST0_CLIENT1__CONFIG_FILE=t0perf-t0client1.rc

declare -r DEFAULT__TRANSPORT="ALL"
declare -r DEFAULT__QPS_PER_TRANSPORT="2000"
declare -r DEFAULT__CONNECTIONS_PER_TRANSPORT="15"
declare -r DEFAULT__MAX_EXECUTION_TIME_MIN="5"

declare -r GMAKE_CMD="${GMAKE_CMD:-gmake} -f ${PERFTEST_DIR}/Makefile UID=${UID} GID=${UID} RUNKEY=${RUNKEY}"
declare -r M4_CMD="${M4_CMD:-m4}"

declare -r USAGE="\
Trust0 performance testing tool.

Usage: $0 [--transport <TRANSPORT>]
          [--qps-per-transport <QPS_PER_TRANSPORT>]
          [--connections-per-transport <CONNECTIONS_PER_TRANSPORT>]
          [--max-execution-time-min <MAX_EXECUTION_TIME_MIN>]
       $0 --help

Options:
  --transport
          Service transport type (values: ALL, tcp, udp).
          [default: ${DEFAULT__TRANSPORT}]
  --qps-per-transport
          Max queries-per-second rate (per transport type).
          [default: ${DEFAULT__QPS_PER_TRANSPORT}]
  --connections-per-transport
          Number of parallel service client connections for load test.
          [default: ${DEFAULT__CONNECTIONS_PER_TRANSPORT}]
  --max-execution-time-min
          Maximum time (in minutes) for testing run.
          [default: ${DEFAULT__MAX_EXECUTION_TIME_MIN}]
  --help
          Show this usage description
"

declare -A program_args=(
  [TRANSPORT]="${DEFAULT__TRANSPORT}"
  [QPS_PER_TRANSPORT]="${DEFAULT__QPS_PER_TRANSPORT}"
  [CONNECTIONS_PER_TRANSPORT]="${DEFAULT__CONNECTIONS_PER_TRANSPORT}"
  [MAX_EXECUTION_TIME_MIN]="${DEFAULT__MAX_EXECUTION_TIME_MIN}"
)

declare -a err_msgs=()

# Display program usage and error and exit
# ----------------------------------------
function exit_on_usage_error {

  echo "${USAGE}" >&2
  for msg in "${err_msgs[@]}"; do
     echo "$msg" >&2
  done

  exit 1
}

# Parse/validate process arguments
# --------------------------------
function validate_invocation {

  local command_args="${1:-}"

  if [ "${command_args}" == "--help" ]; then
    exit_on_usage_error
  fi

  declare -A err_msgs_reference=(
    [TRANSPORT]="Please supply a valid '--transport <TRANSPORT>'"
    [QPS_PER_TRANSPORT]="Please supply a valid '--qps-per-transport <QPS_PER_TRANSPORT>'"
    [CONNECTIONS_PER_TRANSPORT]="Please supply a valid '--connections-per-transport <CONNECTIONS_PER_TRANSPORT>'"
    [MAX_EXECUTION_TIME_MIN]="Please supply a valid '--max-execution-time-min <MAX_EXECUTION_TIME_MIN>'"
  )
  declare -a invocation_err_msgs=()

  while [[ $# -gt 0 ]]; do
    case $1 in
      --transport)
        if [ -n "$2" ] && [[ "$2" =~ ${TRANSPORT_PATTERN} ]]; then
          program_args[TRANSPORT]="$2"
        else
          invocation_err_msgs+=("${err_msgs_reference[TRANSPORT]}")
        fi
        shift; shift
        ;;
      --qps-per-transport)
        if [ -n "$2" ] && [[ "$2" =~ ${QPS_PER_TRANSPORT_PATTERN} ]]; then
          program_args[QPS_PER_TRANSPORT]="$2"
        else
          invocation_err_msgs+=("${err_msgs_reference[QPS_PER_TRANSPORT]}")
        fi
        shift; shift
        ;;
      --connections-per-transport)
        if [ -n "$2" ] && [[ "$2" =~ ${CONNECTIONS_PER_TRANSPORT_PATTERN} ]]; then
          program_args[CONNECTIONS_PER_TRANSPORT]="$2"
        else
          invocation_err_msgs+=("${err_msgs_reference[CONNECTIONS_PER_TRANSPORT]}")
        fi
        shift; shift
        ;;
      --max-execution-time-min)
        if [ -n "$2" ] && [[ "$2" =~ ${MAX_EXECUTION_TIME_MIN_PATTERN} ]]; then
          program_args[MAX_EXECUTION_TIME_MIN]="$2"
        else
          invocation_err_msgs+=("${err_msgs_reference[MAX_EXECUTION_TIME_MIN]}")
        fi
        shift; shift
        ;;
      --help)
        exit_on_usage_error
        ;;
      --*)
        addtl_err_msgs+=( "Unknown option '$1'" )
        shift
        ;;
      *)
        addtl_err_msgs+=( "Unknown argument '$1'" )
        shift
        ;;
    esac
  done

  err_msgs+=( "${invocation_err_msgs[@]}" )

  if [[ ${#err_msgs[@]} -ne 0 ]]; then
    exit_on_usage_error
  fi

  return 0
}

# Build container images
# ----------------------
function build_container_images {

  echo "Building Trust0 container images"
  ${GMAKE_CMD} trust0-tools-image
  ${GMAKE_CMD} trust0-gateway-image
  ${GMAKE_CMD} trust0-client-image

  return 0
}

# Build PKI resources
# -------------------
function build_pki_resources {

  echo "Building Trust0 PKI resources"
  ${GMAKE_CMD} root-ca-pki
  ${GMAKE_CMD} gateway-server-pki
  ${GMAKE_CMD} client-pki

  return 0
}

# Create Trust0 Gateway config file
# ---------------------------------
function create_trust0_gateway_config_file {

  local config_file="${PERFTEST_BUILD_DIR}/$1"

  if [ -f "${config_file}" ]; then
      echo "Skipping Trust0 Gateway config file creation, already exists: path=${config_file}"
      return 1
  fi

  echo "Creating Trust0 Gateway config file: path=${config_file}"
  ${GMAKE_CMD} $config_file

  return 0
}

# Create Trust0 Client config file
# --------------------------------
function create_trust0_client_config_file {

  local config_file="${PERFTEST_BUILD_DIR}/$1"

  if [ -f "${config_file}" ]; then
      echo "Skipping Trust0 Client config file creation, already exists: path=${config_file}"
      return 1
  fi

  echo "Creating Trust0 Client config file: path=${config_file}"
  ${GMAKE_CMD} $config_file

  return 0
}

# Create Trust0 Client (command) script file
# ------------------------------------------
function stage_trust0_client_script_file {

  local script_file="${PERFTEST_BUILD_DIR}/t0perf-t0client-commands.txt"

  echo "Staging Trust0 Client script file: path=${script_file}"
  if [[ ${program_args[TRANSPORT]} == "ALL" ]]; then
    cp "${PERFTEST_DIR}/trust0-client-commands-all.txt" "${script_file}"
  elif [[ ${program_args[TRANSPORT]} == "tcp" ]]; then
    cp "${PERFTEST_DIR}/trust0-client-commands-tcp.txt" "${script_file}"
  else
    cp "${PERFTEST_DIR}/trust0-client-commands-udp.txt" "${script_file}"
  fi

  return 0
}

# Stage DB JSON files
# -------------------
function stage_db_files {

  echo "Staging Trust0 DB files"
  cp "${PERFTEST_DIR}"/trust0-db-access.json "${PERFTEST_BUILD_DIR}"
  cp "${PERFTEST_DIR}"/trust0-db-role.json "${PERFTEST_BUILD_DIR}"
  cp "${PERFTEST_DIR}"/trust0-db-service.json "${PERFTEST_BUILD_DIR}"
  cp "${PERFTEST_DIR}"/trust0-db-user.json "${PERFTEST_BUILD_DIR}"

  return 0
}

# Create Docker Compose file
# --------------------------
function create_docker_compose_file {

  local docker_compose_m4_file;
  if [[ ${program_args[TRANSPORT]} == "ALL" ]]; then
    docker_compose_m4_file="$DOCKER_COMPOSE_ALL_M4_FILE"
  elif [[ ${program_args[TRANSPORT]} == "tcp" ]]; then
    docker_compose_m4_file="$DOCKER_COMPOSE_TCP_M4_FILE"
  else
    docker_compose_m4_file="$DOCKER_COMPOSE_UDP_M4_FILE"
  fi

  echo "Creating Docker Compose file: path=${PERFTEST_DOCKER_COMPOSE_FILE}"
  ${M4_CMD} -D xPERFTEST_BUILD_DIR="${PERFTEST_BUILD_DIR}" -D xUID="${UID}" -D xGID="${UID}" -D xRUNKEY="${RUNKEY}" -D xQPS_PER_TRANSPORT="${program_args[QPS_PER_TRANSPORT]}" -D xCONNECTIONS_PER_TRANSPORT="${program_args[CONNECTIONS_PER_TRANSPORT]}" -D xMAX_EXECUTION_TIME_MIN="${program_args[MAX_EXECUTION_TIME_MIN]}m" "${docker_compose_m4_file}" > "${PERFTEST_DOCKER_COMPOSE_FILE}"

  return 0
}

# Run performance test
# --------------------
function run_performance_test {

  echo "Running performance test: runkey=${RUNKEY}"
  ${GMAKE_CMD} run-performance-test

  return 0
}

# Main program
# ------------
function main {

  mkdir -p "${PERFTEST_BUILD_DIR}"

  validate_invocation "$@"
  build_container_images
  build_pki_resources
  create_trust0_gateway_config_file "${TRUST0_GATEWAY1__CONFIG_FILE}"
  create_trust0_client_config_file "${TRUST0_CLIENT1__CONFIG_FILE}"
  stage_trust0_client_script_file
  stage_db_files
  create_docker_compose_file
  run_performance_test
}

main "$@"
