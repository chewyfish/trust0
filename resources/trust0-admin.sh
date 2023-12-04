#!/usr/bin/env bash

set -euo pipefail

USAGE="\
Trust0 administration tool. Refer to command(s) for further information.

Usage: $0 client-pki-creator (<CLIENT_PKI_OPTIONS>|--help)

       $0 --help

Options:
  --help
          Show this usage description
"

USAGE_CLIENT_PKI_CREATOR="\
Create client certificate and key files usable in a Trust0 environment.

Usage: $0 client-pki-creator --client-cert-filepath <CLIENT_CERT_FILEPATH> --client-key-filepath <CLIENT_KEY_FILEPATH> --ca-cert-filepath <CA_CERT_FILEPATH> --ca-key-filepath <CA_KEY_FILEPATH> --subj-common-name <SUBJ_COMMON_NAME> --auth-user-id <AUTH_USER_ID> --auth-platform <AUTH_PLATFORM> [--subj-country <SUBJ_COUNTRY>] [--subj-state <SUBJ_STATE>] [--subj-city <SUBJ_CITY>] [--subj-company <SUBJ_COMPANY>] [--subj-dept <SUBJ_DEPT>]

       $0 client-pki-creator --help

Options:
  --client-cert-filepath <CLIENT_CERT_FILEPATH>
          The filepath spec for the client certificate file

  --client-key-filepath <CLIENT_KEY_FILEPATH>
          The filepath spec for the client key file

  --ca-cert-filepath <CA_CERT_FILEPATH>
          The filepath spec for the CA certificate file used to sign the client certificate

  --ca-key-filepath <CA_KEY_FILEPATH>
          The filepath spec for the CA key file used to sign the client certificate

  --auth-user-id <AUTH_USER_ID>
          The Trust0 user account ID value

  --auth-platform <AUTH_PLATFORM>
          The machine architecture/platform for the device using the client certificate

  --subj-common-name <SUBJ_COMMON_NAME>
          The client certificate subject common name value

  --subj-country <SUBJ_COUNTRY>
          The client certificate subject country value
          [default: NA]

  --subj-state <SUBJ_STATE>
          The client certificate subject state value
          [default: NA]

  --subj-city <SUBJ_CITY>
          The client certificate subject city value
          [default: NA]

  --subj-company <SUBJ_COMPANY>
          The client certificate subject company value
          [default: NA]

  --subj-dept <SUBJ_DEPT>
          The client certificate subject department value
          [default: NA]

  --help
          Show this usage description
"

OPENSSL_CMD=openssl

COMMAND_CLIENT_PKI_CREATOR="client-pki-creator"
COMMAND=""

declare -a err_msgs=()
declare -A client_pki_creator_args=(
  [SUBJ_COUNTRY]="NA"
  [SUBJ_STATE]="NA"
  [SUBJ_CITY]="NA"
  [SUBJ_COMPANY]="NA"
  [SUBJ_DEPT]="NA"
)

# Display program usage and error and exit
# ----------------------------------------
function exit_on_usage_error {

  local usage
  if [ "${COMMAND}" == "${COMMAND_CLIENT_PKI_CREATOR}" ]; then
    usage="${USAGE_CLIENT_PKI_CREATOR}"
  else
    usage="${USAGE}"
  fi

  echo "$usage"
  for msg in "${err_msgs[@]}"; do
     echo "$msg"
  done

  exit 1
}

# Parse/validate process arguments
#---------------------------------
function validate_invocation {

  local command="${1:-}"

  if [ "${command}" == "--help" ]; then
    exit_on_usage_error

  elif [ -z "${command}" ] || [ "${command}" != "${COMMAND_CLIENT_PKI_CREATOR}" ]; then
    err_msgs+=( "Invalid command supplied")
    exit_on_usage_error

  else
    COMMAND=${COMMAND_CLIENT_PKI_CREATOR}
    shift
    validate_invocation_client_pki_creator "$@"
  fi
}

# Parse/validate process arguments (command: client-pki-creator)
#---------------------------------
function validate_invocation_client_pki_creator {

  declare -A required_err_msgs=(
    [CLIENT_CERT_FILEPATH]="Please supply '--client-cert-filepath <CLIENT_CERT_FILEPATH>'"
    [CLIENT_KEY_FILEPATH]="Please supply '--client-key-filepath <CLIENT_KEY_FILEPATH>'"
    [CA_CERT_FILEPATH]="Please supply '--ca-cert-filepath <CA_CERT_FILEPATH>'"
    [CA_KEY_FILEPATH]="Please supply '--ca-key-filepath <CA_KEY_FILEPATH>'"
    [SUBJ_COMMON_NAME]="Please supply '--subj-common-name <SUBJ_COMMON_NAME>'"
    [AUTH_USER_ID]="Please supply '--auth-user-id <AUTH_USER_ID>'"
    [AUTH_PLATFORM]="Please supply '--auth-platform <AUTH_USER_ID>'"
  )
  declare -a addtl_err_msgs=()

  while [[ $# -gt 0 ]]; do
    case $1 in
      --client-cert-filepath)
        client_pki_creator_args[CLIENT_CERT_FILEPATH]="$2"
        unset "required_err_msgs[CLIENT_CERT_FILEPATH]"
        shift; shift
        ;;
      --client-key-filepath)
        client_pki_creator_args[CLIENT_KEY_FILEPATH]="$2"
        unset "required_err_msgs[CLIENT_KEY_FILEPATH]"
        shift; shift
        ;;
      --ca-cert-filepath)
        client_pki_creator_args[CA_CERT_FILEPATH]="$2"
        unset "required_err_msgs[CA_CERT_FILEPATH]"
        shift; shift
        ;;
      --ca-key-filepath)
        client_pki_creator_args[CA_KEY_FILEPATH]="$2"
        unset "required_err_msgs[CA_KEY_FILEPATH]"
        shift; shift
        ;;
      --auth-user-id)
        client_pki_creator_args[AUTH_USER_ID]="$2"
        unset "required_err_msgs[AUTH_USER_ID]"
        shift; shift
        ;;
      --auth-platform)
        client_pki_creator_args[AUTH_PLATFORM]="$2"
        unset "required_err_msgs[AUTH_PLATFORM]"
        shift; shift
        ;;
      --subj-common-name)
        client_pki_creator_args[SUBJ_COMMON_NAME]="$2"
        unset "required_err_msgs[SUBJ_COMMON_NAME]"
        shift; shift
        ;;
      --subj-country)
        client_pki_creator_args[SUBJ_COUNTRY]="$2"
        shift; shift
        ;;
      --subj-state)
        client_pki_creator_args[SUBJ_STATE]="$2"
        shift; shift
        ;;
      --subj-city)
        client_pki_creator_args[SUBJ_CITY]="$2"
        shift; shift
        ;;
      --subj-company)
        client_pki_creator_args[SUBJ_COMPANY]="$2"
        shift; shift
        ;;
      --subj-dept)
        client_pki_creator_args[SUBJ_DEPT]="$2"
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

  err_msgs+=( "${required_err_msgs[@]}" )
  err_msgs+=( "${addtl_err_msgs[@]}" )

  if [[ ${#err_msgs[@]} -ne 0 ]]; then
    exit_on_usage_error
  fi
}

# create CA certificate openssl config file
# -----------------------------------------
function create_ca_cert_conf_file {

  local ca_cert_file="$1"
  local ca_cert_conf_file="${ca_cert_file}.conf"

  if [ -f "${ca_cert_conf_file}" ]; then
      echo "Skipping CA cert openssl config creation, already exists: path=${ca_cert_conf_file}"
      return
  fi

	echo "Creating CA cert openssl config file: path=${ca_cert_conf_file}"
	cat <<- "EOF" > "${ca_cert_conf_file}"
		[server-cert]
		extendedKeyUsage = serverAuth
		[client-cert]
		extendedKeyUsage = clientAuth
	EOF
}

# create client key file
# ----------------------
function create_client_key_file {

  local client_key_file="$1"

	echo "Creating client key file: path=${client_key_file}"
	${OPENSSL_CMD} genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "${client_key_file}"
}

# create client certificate openssl config file
# ---------------------------------------------
function create_client_cert_conf_file {

  local client_cert_file="$1"
  local client_cert_conf_file="${client_cert_file}.conf"

	echo "Creating client cert openssl config file: path=${client_cert_conf_file}"
	cat <<- EOF > "${client_cert_conf_file}"
		[ req ]
		default_md = sha256
		basicConstraints = CA:FALSE
		keyUsage = critical, digitalSignature, keyEncipherment
		req_extensions = req_ext
		distinguished_name = req_distinguished_name
		prompt = no
		[ req_ext ]
		subjectAltName = @req_alt_names
		[ req_distinguished_name ]
		C = ${client_pki_creator_args[SUBJ_COUNTRY]}
		ST = ${client_pki_creator_args[SUBJ_STATE]}
		L = ${client_pki_creator_args[SUBJ_CITY]}
		O = ${client_pki_creator_args[SUBJ_COMPANY]}
		OU = ${client_pki_creator_args[SUBJ_DEPT]}
		CN = ${client_pki_creator_args[SUBJ_COMMON_NAME]}
		[ req_alt_names ]
		URI = {\"userId\":${client_pki_creator_args[AUTH_USER_ID]},\"platform\":\"${client_pki_creator_args[AUTH_PLATFORM]}\"}
	EOF
}

# create client certificate CSR file
# ----------------------------------
function create_client_cert_csr_file {

  local client_key_file="$1"
  local client_cert_file="$2"
  local client_cert_conf_file="${client_cert_file}.conf"
  local client_cert_csr_file="${client_cert_file}.csr"

	echo "Creating client cert openssl CSR file: path=${client_cert_csr_file}"
	${OPENSSL_CMD} req -key "${client_key_file}" -new -config "${client_cert_conf_file}" -out "${client_cert_csr_file}"
}

# create client certificate file
# ------------------------------
function create_client_cert_file {

  local client_cert_file="$1"
  local ca_key_file="$2"
  local ca_cert_file="$3"
  local client_cert_csr_file="${client_cert_file}.csr"
  local ca_cert_conf_file="${ca_cert_file}.conf"

	echo "Creating client cert file: path=${client_cert_file}"
	${OPENSSL_CMD} x509 -req -in "${client_cert_csr_file}" -CA "${ca_cert_file}" -CAkey "${ca_key_file}" -CAcreateserial -days 365 -copy_extensions copyall -extfile "${ca_cert_conf_file}" -extensions client-cert -out "${client_cert_file}"
}

# main routine
#-------------
function main {

  validate_invocation "$@"

  if [ "${COMMAND}" == "${COMMAND_CLIENT_PKI_CREATOR}" ]; then
    create_ca_cert_conf_file "${client_pki_creator_args[CA_CERT_FILEPATH]}"
    create_client_key_file "${client_pki_creator_args[CLIENT_KEY_FILEPATH]}"
    create_client_cert_conf_file "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}"
    create_client_cert_csr_file "${client_pki_creator_args[CLIENT_KEY_FILEPATH]}" "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}"
    create_client_cert_file "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}" "${client_pki_creator_args[CA_KEY_FILEPATH]}" "${client_pki_creator_args[CA_CERT_FILEPATH]}"
  fi
}

main "$@"
