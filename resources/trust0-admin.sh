#!/usr/bin/env bash

set -euo pipefail

# MODULE: COMMON
# ==============

declare -r USAGE="\
Trust0 administration tool. Refer to command(s) for further information.

Usage: $0 client-pki-creator (<CLIENT_PKI_OPTIONS>|--help)

       $0 --help

Options:
  --help
          Show this usage description
"

declare -r OPENSSL_CMD=openssl

declare -r COMMAND_TOOL__CLIENT_PKI_CREATOR="client-pki-creator"
declare command_tool=""

declare -r DEFAULT__KEY_KEY_ALGORITHM=rsa:4096
declare -r DEFAULT__CERT_EXPIRY_DAYS=365

declare -r KEY_TYPE_RSA=rsa
declare -r KEY_TYPE_EC=ec
declare -r KEY_TYPE_ED=ed
declare -r KEY_ALGORITHM_PATTERN="^(${KEY_TYPE_RSA}|${KEY_TYPE_EC}|${KEY_TYPE_ED}):(.+)$"
declare -r KEY_ALGORITHM_RSA_PARAMS_PATTERN='^[0-9]+$';
declare -r KEY_ALGORITHM_ED_PARAMS_PATTERN='^(ed25519|ed448)$';

declare result_key_type=""
declare result_key_params=""
declare -a err_msgs=()

# COMMON: Display program usage and error and exit
# ------------------------------------------------
function cmn__exit_on_usage_error {

  local usage
  if [ "${command_tool}" == "${COMMAND_TOOL__CLIENT_PKI_CREATOR}" ]; then
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

# COMMON: Parse/validate process arguments
# ----------------------------------------
function cmn__validate_invocation {

  local command_args="${1:-}"

  if [ "${command_args}" == "--help" ]; then
    cmn__exit_on_usage_error

  elif [ -z "${command_args}" ] || [ "${command_args}" != "${COMMAND_TOOL__CLIENT_PKI_CREATOR}" ]; then
    err_msgs+=( "Invalid sub-command supplied")
    cmn__exit_on_usage_error

  else
    command_tool=${COMMAND_TOOL__CLIENT_PKI_CREATOR}
    shift
    clipki__validate_invocation "$@"
  fi
}

# COMMON: create CA certificate signing openssl config file
# ---------------------------------------------------------
function cmn__create_ca_cert_signing_conf_file {

  local ca_cert_file="$1"
  local ca_cert_conf_file="${ca_cert_file}.conf"

  if [ -f "${ca_cert_conf_file}" ]; then
      echo "Skipping CA cert signing openssl config creation, already exists: path=${ca_cert_conf_file}"
      return
  fi

	echo "Creating CA cert signing openssl config file: path=${ca_cert_conf_file}"
	cat <<- "EOF" > "${ca_cert_conf_file}"
		[server-cert]
		extendedKeyUsage = serverAuth
		[client-cert]
		extendedKeyUsage = clientAuth
	EOF
}

# COMMON: parse key algorithm
# ---------------------------
function cmn__parse_key_algorithm_arg {

  local key_alg_arg=${1,,}
  local key_type_var="${2:-result_key_type}"
  local key_params_var="${3:-result_key_params}"

  if [[ "${key_alg_arg}" =~ ${KEY_ALGORITHM_PATTERN} ]]; then

    local key_type="${BASH_REMATCH[1]}"
    local key_params="${BASH_REMATCH[2]}"
    eval "${key_type_var}"="${key_type}"
    eval "${key_params_var}"="${key_params}"

    if [ "${key_type}" == "${KEY_TYPE_RSA}" ]; then
      if [[ "${key_params}" =~ ${KEY_ALGORITHM_RSA_PARAMS_PATTERN} ]]; then
        return 0
      fi
    elif [ "${key_type}" == "${KEY_TYPE_EC}" ]; then
      if [ -r "${key_params}" ]; then
        return 0
      fi
    elif [[ "${key_params}" =~ ${KEY_ALGORITHM_ED_PARAMS_PATTERN} ]]; then
      return 0
    fi
  fi

  err_msgs+=( "Invalid key algorithm supplied: alg=${key_alg_arg}")
  cmn__exit_on_usage_error
}

# COMMON: create private key file
# -------------------------------
function cmn__create_private_key_file {

  local key_file="$1"
  local key_alg="$2"

	echo "Creating private key file: path=${key_file}, alg=${key_alg}"

  cmn__parse_key_algorithm_arg "${key_alg}"

	if [ "${result_key_type}" == "${KEY_TYPE_RSA}" ]; then
	  ${OPENSSL_CMD} genrsa -out "${key_file}" "${result_key_params}"
	elif [ "${result_key_type}" == "${KEY_TYPE_EC}" ]; then
	  ${OPENSSL_CMD} ecparam -in "${result_key_params}" -genkey -noout -out "${key_file}"
	elif [ "${result_key_type}" == "${KEY_TYPE_ED}" ]; then
	  ${OPENSSL_CMD} genpkey -algorithm "${result_key_params}" -out "${key_file}"
  else
    err_msgs+=( "Invalid key type supplied: val=${result_key_type}")
    cmn__exit_on_usage_error
	fi
}

# COMMON: create certificate CSR file
# ----------------------------------
function cmn__create_cert_csr_file {

  local key_file="$1"
  local cert_file="$2"
  local cert_conf_file="${cert_file}.conf"
  local cert_csr_file="${cert_file}.csr"

	echo "Creating cert openssl CSR file: path=${cert_csr_file}"
	${OPENSSL_CMD} req -key "${key_file}" -new -config "${cert_conf_file}" -out "${cert_csr_file}"
}

# COMMON: create non-CA certificate file
# --------------------------------------
function cmn__create_non_ca_cert_file {

  local cert_file="$1"
  local cert_type="$2"
  local ca_key_file="$3"
  local ca_cert_file="$4"
  local cert_csr_file="${cert_file}.csr"
  local ca_cert_conf_file="${ca_cert_file}.conf"

	echo "Creating non-CA cert file: path=${cert_file}"
	${OPENSSL_CMD} x509 -req -in "${cert_csr_file}" -CA "${ca_cert_file}" -CAkey "${ca_key_file}" -CAcreateserial -days 365 -copy_extensions copyall -extfile "${ca_cert_conf_file}" -extensions "${cert_type}" -out "${cert_file}"
}

# MODULE: ROOT CA PKI CREATOR
# ===========================

# MODULE: GATEWAY PKI CREATOR
# ===========================

# MODULE: CLIENT PKI CREATOR
# ==========================

declare -r USAGE_CLIENT_PKI_CREATOR="\
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

  --key-algorithm <KEY_ALGORITHM>
          Private key algorithm (values: 'rsa:<RSA_SIZE>', 'ec:<EC_PARAMS_FILEPATH>', ed:<ED_SCHEME>)
          RSA_SIZE: valid key bit length for RSA key
          EC_PARAMS_FILEPATH: File path to an openssl EC params file
          ED_SCHEME: ED scheme to use. Ex) ed25519, ed448
          [default: ${DEFAULT__KEY_KEY_ALGORITHM}]

  --cert-expiry-days <CERT_EXPIRY_DAYS>
          Number of days certificate is valid
          [default: ${DEFAULT__CERT_EXPIRY_DAYS}]

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

declare -A client_pki_creator_args=(
  [KEY_ALGORITHM]="${DEFAULT__KEY_KEY_ALGORITHM}"
  [CERT_EXPIRY_DAYS]="${DEFAULT__CERT_EXPIRY_DAYS}"
  [SUBJ_COUNTRY]="NA"
  [SUBJ_STATE]="NA"
  [SUBJ_CITY]="NA"
  [SUBJ_COMPANY]="NA"
  [SUBJ_DEPT]="NA"
)

# CLIENT PKI: Parse/validate process arguments
# --------------------------------------------
function clipki__validate_invocation {

  declare -A required_err_msgs=(
    [CLIENT_CERT_FILEPATH]="Please supply '--client-cert-filepath <CLIENT_CERT_FILEPATH>'"
    [CLIENT_KEY_FILEPATH]="Please supply '--client-key-filepath <CLIENT_KEY_FILEPATH>'"
    [CA_CERT_FILEPATH]="Please supply '--ca-cert-filepath <CA_CERT_FILEPATH>'"
    [CA_KEY_FILEPATH]="Please supply '--ca-key-filepath <CA_KEY_FILEPATH>'"
    [SUBJ_COMMON_NAME]="Please supply '--subj-common-name <SUBJ_COMMON_NAME>'"
    [AUTH_USER_ID]="Please supply '--auth-user-id <AUTH_USER_ID>'"
    [AUTH_PLATFORM]="Please supply '--auth-platform <AUTH_PLATFORM>'"
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
      --key-algorithm)
        client_pki_creator_args[KEY_ALGORITHM]="$2"
        shift; shift
        ;;
      --cert-expiry-days)
        client_pki_creator_args[CERT_EXPIRY_DAYS]="$2"
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
        cmn__exit_on_usage_error
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
    cmn__exit_on_usage_error
  fi
}

# CLIENT PKI: create certificate openssl config file
# --------------------------------------------------
function clipki__create_cert_openssl_conf {

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

# MODULE: MAIN
# ============
function main {

  cmn__validate_invocation "$@"

  if [ "${command_tool}" == "${COMMAND_TOOL__CLIENT_PKI_CREATOR}" ]; then
    cmn__create_ca_cert_signing_conf_file "${client_pki_creator_args[CA_CERT_FILEPATH]}"
    cmn__create_private_key_file "${client_pki_creator_args[CLIENT_KEY_FILEPATH]}" "${client_pki_creator_args[KEY_ALGORITHM]}"
    clipki__create_cert_openssl_conf "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}"
    cmn__create_cert_csr_file "${client_pki_creator_args[CLIENT_KEY_FILEPATH]}" "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}"
    cmn__create_non_ca_cert_file "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}" client-cert "${client_pki_creator_args[CA_KEY_FILEPATH]}" "${client_pki_creator_args[CA_CERT_FILEPATH]}"
  fi
}

main "$@"
