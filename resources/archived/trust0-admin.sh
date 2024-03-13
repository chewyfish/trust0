#!/usr/bin/env bash

set -euo pipefail

# MODULE: COMMON
# ==============

declare -r USAGE="\
Trust0 administration tool. Refer to command(s) for further information.

Usage: $0 rootca-pki-creator (<ROOTCA_PKI_OPTIONS>|--help)
       $0 gateway-pki-creator (<GATEWAY_PKI_OPTIONS>|--help)
       $0 client-pki-creator (<CLIENT_PKI_OPTIONS>|--help)
       $0 --help

Options:
  --help
          Show this usage description
"

declare -r OPENSSL_CMD=openssl

declare -r COMMAND_TOOL__ROOTCA_PKI_CREATOR="rootca-pki-creator"
declare -r COMMAND_TOOL__GATEWAY_PKI_CREATOR="gateway-pki-creator"
declare -r COMMAND_TOOL__CLIENT_PKI_CREATOR="client-pki-creator"
declare command_tool=""

declare -r DEFAULT__KEY_ALGORITHM=rsa:4096
declare -r DEFAULT__CERT_EXPIRY_DAYS=365
declare -r DEFAULT__MD_ALGORITHM=sha256

declare -r KEY_TYPE_RSA=rsa
declare -r KEY_TYPE_EC=ec
declare -r KEY_TYPE_ED=ed
declare -r KEY_ALGORITHM_PATTERN="^(${KEY_TYPE_RSA}|${KEY_TYPE_EC}|${KEY_TYPE_ED}):(.+)$"
declare -r KEY_ALGORITHM_RSA_PARAMS_PATTERN='^[0-9]+$';
declare -r KEY_ALGORITHM_ED_PARAMS_PATTERN='^(ed25519)$';

declare result_key_type=""
declare result_key_params=""
declare -a err_msgs=()

# COMMON: Display program usage and error and exit
# ------------------------------------------------
function cmn__exit_on_usage_error {

  local usage
  if [ "${command_tool}" == "${COMMAND_TOOL__ROOTCA_PKI_CREATOR}" ]; then
    usage="${USAGE_ROOTCA_PKI_CREATOR}"
  elif [ "${command_tool}" == "${COMMAND_TOOL__GATEWAY_PKI_CREATOR}" ]; then
    usage="${USAGE_GATEWAY_PKI_CREATOR}"
  elif [ "${command_tool}" == "${COMMAND_TOOL__CLIENT_PKI_CREATOR}" ]; then
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

  elif [ -z "${command_args}" ] || {
      [ "${command_args}" != "${COMMAND_TOOL__ROOTCA_PKI_CREATOR}" ] &&
      [ "${command_args}" != "${COMMAND_TOOL__GATEWAY_PKI_CREATOR}" ] &&
      [ "${command_args}" != "${COMMAND_TOOL__CLIENT_PKI_CREATOR}" ] ; }; then
    err_msgs+=( "Invalid sub-command supplied")
    cmn__exit_on_usage_error

  else
    shift

    if [ "${command_args}" == "${COMMAND_TOOL__ROOTCA_PKI_CREATOR}" ]; then
      command_tool=${COMMAND_TOOL__ROOTCA_PKI_CREATOR}
      rootca__validate_invocation "$@"

    elif [ "${command_args}" == "${COMMAND_TOOL__GATEWAY_PKI_CREATOR}" ]; then
      command_tool=${COMMAND_TOOL__GATEWAY_PKI_CREATOR}
      gateway__validate_invocation "$@"

    else
      command_tool=${COMMAND_TOOL__CLIENT_PKI_CREATOR}
      client__validate_invocation "$@"
    fi
  fi
}

# COMMON: create CA certificate CSR openssl config file
# -----------------------------------------------------
function cmn__create_ca_cert_csr_conf_file {

  local ca_cert_file="$1"
  local ca_cert_csr_conf_file="${ca_cert_file}.csr.conf"

  if [ -f "${ca_cert_csr_conf_file}" ]; then
      echo "Skipping certificate CSR config creation, already exists: path=${ca_cert_csr_conf_file}"
      return 1
  fi

	echo "Creating certificate CSR openssl config file: path=${ca_cert_csr_conf_file}"
	cat <<- "EOF" > "${ca_cert_csr_conf_file}"
[gateway-cert]
extendedKeyUsage = serverAuth
[client-cert]
extendedKeyUsage = clientAuth
EOF

	return 0
}

# COMMON: parse key algorithm
# ---------------------------
function cmn__parse_key_algorithm_arg {

  local key_alg_arg="$1"
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

  if [ -f "${key_file}" ]; then
      echo "Skipping private key creation, already exists: path=${key_file}"
      return 1
  fi

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

	return 0
}

# COMMON: create certificate CSR file
# ----------------------------------
function cmn__create_cert_csr_file {

  local key_file="$1"
  local cert_file="$2"
  local cert_conf_file="${cert_file}.conf"
  local cert_csr_file="${cert_file}.csr"

  if [ -f "${cert_csr_file}" ]; then
      echo "Skipping certificate CSR creation, already exists: path=${cert_csr_file}"
      return 1
  fi

	echo "Creating certificate CSR file: path=${cert_csr_file}"
	${OPENSSL_CMD} req -key "${key_file}" -new -config "${cert_conf_file}" -out "${cert_csr_file}"

	return 0
}

# COMMON: create non-CA certificate file
# --------------------------------------
function cmn__create_non_ca_cert_file {

  local cert_file="$1"
  local cert_type="$2"
  local cert_expiry_days="$3"
  local ca_key_file="$4"
  local ca_cert_file="$5"
  local cert_csr_file="${cert_file}.csr"
  local ca_cert_csr_conf_file="${ca_cert_file}.csr.conf"

  if [ -f "${cert_file}" ]; then
      echo "Skipping certificate creation, already exists: path=${cert_file}"
      return 1
  fi

	echo "Creating non-CA certificate file: path=${cert_file}"
	${OPENSSL_CMD} x509 -req -in "${cert_csr_file}" -CA "${ca_cert_file}" -CAkey "${ca_key_file}" -CAcreateserial -days "${cert_expiry_days}" -copy_extensions copyall -extfile "${ca_cert_csr_conf_file}" -extensions "${cert_type}" -out "${cert_file}"

	return 0
}

# MODULE: ROOT CA PKI CREATOR
# ===========================

declare -r USAGE_ROOTCA_PKI_CREATOR="\
Create root CA certificate and key files usable in a Trust0 environment.

Usage: $0 rootca-pki-creator --rootca-cert-filepath <ROOTCA_CERT_FILEPATH> --rootca-key-filepath <ROOTCA_KEY_FILEPATH> [--key-algorithm <KEY_ALGORITHM>] [--md-algorithm <MD_ALGORITHM>] [--cert-expiry-days <CERT_EXPIRY_DAYS>] --subj-common-name <SUBJ_COMMON_NAME> [--subj-country <SUBJ_COUNTRY>] [--subj-state <SUBJ_STATE>] [--subj-city <SUBJ_CITY>] [--subj-company <SUBJ_COMPANY>] [--subj-dept <SUBJ_DEPT>]

       $0 rootca-pki-creator --help

Options:
  --rootca-cert-filepath <ROOTCA_CERT_FILEPATH>
          The filepath spec for the rootca certificate file

  --rootca-key-filepath <ROOTCA_KEY_FILEPATH>
          The filepath spec for the rootca key file

  --key-algorithm <KEY_ALGORITHM>
          Private key algorithm (values: 'rsa:<RSA_SIZE>', 'ec:<EC_PARAMS_FILEPATH>', ed:<ED_SCHEME>)
          RSA_SIZE: valid key bit length for RSA key
          EC_PARAMS_FILEPATH: File path to an openssl EC params file (curves 'prime256v1' and 'secp384r1' tested)
          ED_SCHEME: ED scheme to use. (currently only 'ed25519' supported)
          [default: ${DEFAULT__KEY_ALGORITHM}]

  --md-algorithm <MD_ALGORITHM>
          Valid openssl message digest hash algorithm to use where necessary in PKI resource creation
          [default: '${DEFAULT__MD_ALGORITHM}']

  --cert-expiry-days <CERT_EXPIRY_DAYS>
          Number of days certificate is valid
          [default: ${DEFAULT__CERT_EXPIRY_DAYS}]

  --subj-common-name <SUBJ_COMMON_NAME>
          The rootca certificate subject common name value

  --subj-country <SUBJ_COUNTRY>
          The rootca certificate subject country value
          [default: NA]

  --subj-state <SUBJ_STATE>
          The rootca certificate subject state value
          [default: NA]

  --subj-city <SUBJ_CITY>
          The rootca certificate subject city value
          [default: NA]

  --subj-company <SUBJ_COMPANY>
          The rootca certificate subject company value
          [default: NA]

  --subj-dept <SUBJ_DEPT>
          The rootca certificate subject department value
          [default: NA]

  --help
          Show this usage description
"

declare -A rootca_pki_creator_args=(
  [KEY_ALGORITHM]="${DEFAULT__KEY_ALGORITHM}"
  [CERT_EXPIRY_DAYS]="${DEFAULT__CERT_EXPIRY_DAYS}"
  [MD_ALGORITHM]="${DEFAULT__MD_ALGORITHM}"
  [SUBJ_COUNTRY]="NA"
  [SUBJ_STATE]="NA"
  [SUBJ_CITY]="NA"
  [SUBJ_COMPANY]="NA"
  [SUBJ_DEPT]="NA"
)

# ROOTCA PKI: Parse/validate process arguments
# --------------------------------------------
function rootca__validate_invocation {

  declare -A required_err_msgs=(
    [ROOTCA_CERT_FILEPATH]="Please supply '--rootca-cert-filepath <ROOTCA_CERT_FILEPATH>'"
    [ROOTCA_KEY_FILEPATH]="Please supply '--rootca-key-filepath <ROOTCA_KEY_FILEPATH>'"
    [SUBJ_COMMON_NAME]="Please supply '--subj-common-name <SUBJ_COMMON_NAME>'"
  )
  declare -a addtl_err_msgs=()

  while [[ $# -gt 0 ]]; do
    case $1 in
      --rootca-cert-filepath)
        rootca_pki_creator_args[ROOTCA_CERT_FILEPATH]="$2"
        unset "required_err_msgs[ROOTCA_CERT_FILEPATH]"
        shift; shift
        ;;
      --rootca-key-filepath)
        rootca_pki_creator_args[ROOTCA_KEY_FILEPATH]="$2"
        unset "required_err_msgs[ROOTCA_KEY_FILEPATH]"
        shift; shift
        ;;
      --key-algorithm)
        rootca_pki_creator_args[KEY_ALGORITHM]="$2"
        shift; shift
        ;;
      --md-algorithm)
        client_pki_creator_args[MD_ALGORITHM]="$2"
        shift; shift
        ;;
      --cert-expiry-days)
        rootca_pki_creator_args[CERT_EXPIRY_DAYS]="$2"
        shift; shift
        ;;
      --subj-common-name)
        rootca_pki_creator_args[SUBJ_COMMON_NAME]="$2"
        unset "required_err_msgs[SUBJ_COMMON_NAME]"
        shift; shift
        ;;
      --subj-country)
        rootca_pki_creator_args[SUBJ_COUNTRY]="$2"
        shift; shift
        ;;
      --subj-state)
        rootca_pki_creator_args[SUBJ_STATE]="$2"
        shift; shift
        ;;
      --subj-city)
        rootca_pki_creator_args[SUBJ_CITY]="$2"
        shift; shift
        ;;
      --subj-company)
        rootca_pki_creator_args[SUBJ_COMPANY]="$2"
        shift; shift
        ;;
      --subj-dept)
        rootca_pki_creator_args[SUBJ_DEPT]="$2"
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

# ROOTCA PKI: create certificate openssl config file
# --------------------------------------------------
function rootca__create_cert_openssl_conf {

  local cert_file="$1"
  local cert_conf_file="${cert_file}.conf"

  if [ -f "${cert_conf_file}" ]; then
      echo "Skipping certificate config creation, already exists: path=${cert_conf_file}"
      return 1
  fi

	echo "Creating root CA certificate openssl config file: path=${cert_conf_file}"
	cat <<- EOF > "${cert_conf_file}"
[ req ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
default_md = ${rootca_pki_creator_args[MD_ALGORITHM]}
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign
extendedKeyUsage = critical, serverAuth, clientAuth
distinguished_name = req_distinguished_name
prompt = no
[ req_distinguished_name ]
C = ${rootca_pki_creator_args[SUBJ_COUNTRY]}
ST = ${rootca_pki_creator_args[SUBJ_STATE]}
L = ${rootca_pki_creator_args[SUBJ_CITY]}
O = ${rootca_pki_creator_args[SUBJ_COMPANY]}
OU = ${rootca_pki_creator_args[SUBJ_DEPT]}
CN = ${rootca_pki_creator_args[SUBJ_COMMON_NAME]}
EOF

	return 0
}

# ROOTCA PKI: create certificate file
# -----------------------------------
function rootca__create_cert_file {

  local key_file="$1"
  local cert_file="$2"
  local cert_expiry_days="$3"
  local cert_md_alg="$4"
  local cert_conf_file="${cert_file}.conf"

  if [ -f "${cert_file}" ]; then
      echo "Skipping certificate creation, already exists: path=${cert_file}"
      return 1
  fi

	echo "Creating root CA certificate file: path=${cert_file}"
	${OPENSSL_CMD} req -x509 -new -nodes -key "${key_file}" -"${cert_md_alg}" -days "${cert_expiry_days}" -out "${cert_file}" -config "${cert_conf_file}"

	return 0
}

# MODULE: GATEWAY PKI CREATOR
# ===========================

declare -r USAGE_GATEWAY_PKI_CREATOR="\
Create gateway certificate and key files usable in a Trust0 environment.

Usage: $0 gateway-pki-creator --gateway-cert-filepath <GATEWAY_CERT_FILEPATH> --gateway-key-filepath <GATEWAY_KEY_FILEPATH> [--key-algorithm <KEY_ALGORITHM>] [--md-algorithm <MD_ALGORITHM>] [--cert-expiry-days <CERT_EXPIRY_DAYS>] --ca-cert-filepath <CA_CERT_FILEPATH> --ca-key-filepath <CA_KEY_FILEPATH> --subj-common-name <SUBJ_COMMON_NAME> [--subj-country <SUBJ_COUNTRY>] [--subj-state <SUBJ_STATE>] [--subj-city <SUBJ_CITY>] [--subj-company <SUBJ_COMPANY>] [--subj-dept <SUBJ_DEPT>] [--san-dns1 <SAN_DNS1>] [--san-dns2 <SAN_DNS2>]

       $0 gateway-pki-creator --help

Options:
  --gateway-cert-filepath <GATEWAY_CERT_FILEPATH>
          The filepath spec for the gateway certificate file

  --gateway-key-filepath <GATEWAY_KEY_FILEPATH>
          The filepath spec for the gateway key file

  --ca-cert-filepath <CA_CERT_FILEPATH>
          The filepath spec for the CA certificate file used to sign the gateway certificate

  --ca-key-filepath <CA_KEY_FILEPATH>
          The filepath spec for the CA key file used to sign the gateway certificate

  --key-algorithm <KEY_ALGORITHM>
          Private key algorithm (values: 'rsa:<RSA_SIZE>', 'ec:<EC_PARAMS_FILEPATH>', ed:<ED_SCHEME>)
          RSA_SIZE: valid key bit length for RSA key
          EC_PARAMS_FILEPATH: File path to an openssl EC params file (curves 'prime256v1' and 'secp384r1' tested)
          ED_SCHEME: ED scheme to use. (currently only 'ed25519' supported)
          [default: ${DEFAULT__KEY_ALGORITHM}]

  --md-algorithm <MD_ALGORITHM>
          Valid openssl message digest hash algorithm to use where necessary in PKI resource creation
          [default: '${DEFAULT__MD_ALGORITHM}']

  --cert-expiry-days <CERT_EXPIRY_DAYS>
          Number of days certificate is valid
          [default: ${DEFAULT__CERT_EXPIRY_DAYS}]

  --subj-common-name <SUBJ_COMMON_NAME>
          The gateway certificate subject common name value

  --subj-country <SUBJ_COUNTRY>
          The gateway certificate subject country value
          [default: NA]

  --subj-state <SUBJ_STATE>
          The gateway certificate subject state value
          [default: NA]

  --subj-city <SUBJ_CITY>
          The gateway certificate subject city value
          [default: NA]

  --subj-company <SUBJ_COMPANY>
          The gateway certificate subject company value
          [default: NA]

  --subj-dept <SUBJ_DEPT>
          The gateway certificate subject department value
          [default: NA]

  --san-dns1 <SAN_DNS1>
          First DNS SAN (Subject Alternative Name) value
          [default: '127.0.0.1']
  --san-dns2 <SAN_DNS2>
          Second DNS SAN (Subject Alternative Name) value
          [default: '::1']

  --help
          Show this usage description
"

declare -A gateway_pki_creator_args=(
  [KEY_ALGORITHM]="${DEFAULT__KEY_ALGORITHM}"
  [CERT_EXPIRY_DAYS]="${DEFAULT__CERT_EXPIRY_DAYS}"
  [MD_ALGORITHM]="${DEFAULT__MD_ALGORITHM}"
  [SUBJ_COUNTRY]="NA"
  [SUBJ_STATE]="NA"
  [SUBJ_CITY]="NA"
  [SUBJ_COMPANY]="NA"
  [SUBJ_DEPT]="NA"
  [SAN_DNS1]="127.0.0.1"
  [SAN_DNS2]="::1"
)

# GATEWAY PKI: Parse/validate process arguments
# --------------------------------------------
function gateway__validate_invocation {

  declare -A required_err_msgs=(
    [GATEWAY_CERT_FILEPATH]="Please supply '--gateway-cert-filepath <GATEWAY_CERT_FILEPATH>'"
    [GATEWAY_KEY_FILEPATH]="Please supply '--gateway-key-filepath <GATEWAY_KEY_FILEPATH>'"
    [CA_CERT_FILEPATH]="Please supply '--ca-cert-filepath <CA_CERT_FILEPATH>'"
    [CA_KEY_FILEPATH]="Please supply '--ca-key-filepath <CA_KEY_FILEPATH>'"
    [SUBJ_COMMON_NAME]="Please supply '--subj-common-name <SUBJ_COMMON_NAME>'"
  )
  declare -a addtl_err_msgs=()

  while [[ $# -gt 0 ]]; do
    case $1 in
      --gateway-cert-filepath)
        gateway_pki_creator_args[GATEWAY_CERT_FILEPATH]="$2"
        unset "required_err_msgs[GATEWAY_CERT_FILEPATH]"
        shift; shift
        ;;
      --gateway-key-filepath)
        gateway_pki_creator_args[GATEWAY_KEY_FILEPATH]="$2"
        unset "required_err_msgs[GATEWAY_KEY_FILEPATH]"
        shift; shift
        ;;
      --ca-cert-filepath)
        gateway_pki_creator_args[CA_CERT_FILEPATH]="$2"
        unset "required_err_msgs[CA_CERT_FILEPATH]"
        shift; shift
        ;;
      --ca-key-filepath)
        gateway_pki_creator_args[CA_KEY_FILEPATH]="$2"
        unset "required_err_msgs[CA_KEY_FILEPATH]"
        shift; shift
        ;;
      --key-algorithm)
        gateway_pki_creator_args[KEY_ALGORITHM]="$2"
        shift; shift
        ;;
      --md-algorithm)
        client_pki_creator_args[MD_ALGORITHM]="$2"
        shift; shift
        ;;
      --cert-expiry-days)
        gateway_pki_creator_args[CERT_EXPIRY_DAYS]="$2"
        shift; shift
        ;;
      --subj-common-name)
        gateway_pki_creator_args[SUBJ_COMMON_NAME]="$2"
        unset "required_err_msgs[SUBJ_COMMON_NAME]"
        shift; shift
        ;;
      --subj-country)
        gateway_pki_creator_args[SUBJ_COUNTRY]="$2"
        shift; shift
        ;;
      --subj-state)
        gateway_pki_creator_args[SUBJ_STATE]="$2"
        shift; shift
        ;;
      --subj-city)
        gateway_pki_creator_args[SUBJ_CITY]="$2"
        shift; shift
        ;;
      --subj-company)
        gateway_pki_creator_args[SUBJ_COMPANY]="$2"
        shift; shift
        ;;
      --subj-dept)
        gateway_pki_creator_args[SUBJ_DEPT]="$2"
        shift; shift
        ;;
      --san-dns1)
        gateway_pki_creator_args[SAN_DNS1]="$2"
        shift; shift
        ;;
      --san-dns2)
        gateway_pki_creator_args[SAN_DNS2]="$2"
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

# GATEWAY PKI: create certificate openssl config file
# --------------------------------------------------
function gateway__create_cert_openssl_conf {

  local cert_file="$1"
  local cert_conf_file="${cert_file}.conf"

  if [ -f "${cert_conf_file}" ]; then
      echo "Skipping certificate config creation, already exists: path=${cert_conf_file}"
      return 1
  fi

	echo "Creating gateway certificate openssl config file: path=${cert_conf_file}"
	cat <<- EOF > "${cert_conf_file}"
[ req ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
default_md = ${gateway_pki_creator_args[MD_ALGORITHM]}
basicConstraints = CA:false
keyUsage = cRLSign, keyCertSign, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign
extendedKeyUsage = critical, serverAuth, clientAuth
req_extensions = req_ext
distinguished_name = req_distinguished_name
prompt = no
[ req_ext ]
subjectAltName = @req_alt_names
[ req_distinguished_name ]
C = ${gateway_pki_creator_args[SUBJ_COUNTRY]}
ST = ${gateway_pki_creator_args[SUBJ_STATE]}
L = ${gateway_pki_creator_args[SUBJ_CITY]}
O = ${gateway_pki_creator_args[SUBJ_COMPANY]}
OU = ${gateway_pki_creator_args[SUBJ_DEPT]}
CN = ${gateway_pki_creator_args[SUBJ_COMMON_NAME]}
[ req_alt_names ]
DNS.1 =  ${gateway_pki_creator_args[SAN_DNS1]}
DNS.2 =  ${gateway_pki_creator_args[SAN_DNS2]}
EOF

	return 0
}

# MODULE: CLIENT PKI CREATOR
# ==========================

declare -r USAGE_CLIENT_PKI_CREATOR="\
Create client certificate and key files usable in a Trust0 environment.

Usage: $0 client-pki-creator --client-cert-filepath <CLIENT_CERT_FILEPATH> --client-key-filepath <CLIENT_KEY_FILEPATH> [--key-algorithm <KEY_ALGORITHM>] [--md-algorithm <MD_ALGORITHM>] [--cert-expiry-days <CERT_EXPIRY_DAYS>] --ca-cert-filepath <CA_CERT_FILEPATH> --ca-key-filepath <CA_KEY_FILEPATH> --subj-common-name <SUBJ_COMMON_NAME> --auth-user-id <AUTH_USER_ID> --auth-platform <AUTH_PLATFORM> [--subj-country <SUBJ_COUNTRY>] [--subj-state <SUBJ_STATE>] [--subj-city <SUBJ_CITY>] [--subj-company <SUBJ_COMPANY>] [--subj-dept <SUBJ_DEPT>]

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
          EC_PARAMS_FILEPATH: File path to an openssl EC params file (curves 'prime256v1' and 'secp384r1' tested)
          ED_SCHEME: ED scheme to use. (currently only 'ed25519' supported)
          [default: '${DEFAULT__KEY_ALGORITHM}']

  --md-algorithm <MD_ALGORITHM>
          Valid openssl message digest hash algorithm to use where necessary in PKI resource creation
          [default: '${DEFAULT__MD_ALGORITHM}']

  --cert-expiry-days <CERT_EXPIRY_DAYS>
          Number of days certificate is valid
          [default: '${DEFAULT__CERT_EXPIRY_DAYS}']

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
  [KEY_ALGORITHM]="${DEFAULT__KEY_ALGORITHM}"
  [CERT_EXPIRY_DAYS]="${DEFAULT__CERT_EXPIRY_DAYS}"
  [MD_ALGORITHM]="${DEFAULT__MD_ALGORITHM}"
  [SUBJ_COUNTRY]="NA"
  [SUBJ_STATE]="NA"
  [SUBJ_CITY]="NA"
  [SUBJ_COMPANY]="NA"
  [SUBJ_DEPT]="NA"
)

# CLIENT PKI: Parse/validate process arguments
# --------------------------------------------
function client__validate_invocation {

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
      --md-algorithm)
        client_pki_creator_args[MD_ALGORITHM]="$2"
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
function client__create_cert_openssl_conf {

  local cert_file="$1"
  local cert_conf_file="${cert_file}.conf"

  if [ -f "${cert_conf_file}" ]; then
      echo "Skipping certificate config creation, already exists: path=${cert_conf_file}"
      return 1
  fi

	echo "Creating client certificate openssl config file: path=${cert_conf_file}"
	cat <<- EOF > "${cert_conf_file}"
[ req ]
default_md = ${client_pki_creator_args[MD_ALGORITHM]}
basicConstraints = critical, CA:false
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = critical, clientAuth
req_extensions = req_ext
distinguished_name = req_distinguished_name
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
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

	return 0
}

# MODULE: MAIN
# ============

function main {

  cmn__validate_invocation "$@"

  if [ "${command_tool}" == "${COMMAND_TOOL__ROOTCA_PKI_CREATOR}" ]; then
    if cmn__create_private_key_file "${rootca_pki_creator_args[ROOTCA_KEY_FILEPATH]}" "${rootca_pki_creator_args[KEY_ALGORITHM]}"; then
      rm -f "${rootca_pki_creator_args[ROOTCA_CERT_FILEPATH]}"
    fi
    rootca__create_cert_openssl_conf "${rootca_pki_creator_args[ROOTCA_CERT_FILEPATH]}" || true
    rootca__create_cert_file "${rootca_pki_creator_args[ROOTCA_KEY_FILEPATH]}" "${rootca_pki_creator_args[ROOTCA_CERT_FILEPATH]}" "${rootca_pki_creator_args[CERT_EXPIRY_DAYS]}"  "${rootca_pki_creator_args[MD_ALGORITHM]}" || true

  elif [ "${command_tool}" == "${COMMAND_TOOL__GATEWAY_PKI_CREATOR}" ]; then
    cmn__create_ca_cert_csr_conf_file "${gateway_pki_creator_args[CA_CERT_FILEPATH]}" || true
    if cmn__create_private_key_file "${gateway_pki_creator_args[GATEWAY_KEY_FILEPATH]}" "${gateway_pki_creator_args[KEY_ALGORITHM]}"; then
      rm -f "${gateway_pki_creator_args[GATEWAY_CERT_FILEPATH]}" "${gateway_pki_creator_args[GATEWAY_CERT_FILEPATH]}".csr
    fi
    gateway__create_cert_openssl_conf "${gateway_pki_creator_args[GATEWAY_CERT_FILEPATH]}" || true
    cmn__create_cert_csr_file "${gateway_pki_creator_args[GATEWAY_KEY_FILEPATH]}" "${gateway_pki_creator_args[GATEWAY_CERT_FILEPATH]}" || true
    cmn__create_non_ca_cert_file "${gateway_pki_creator_args[GATEWAY_CERT_FILEPATH]}" gateway-cert "${gateway_pki_creator_args[CERT_EXPIRY_DAYS]}" "${gateway_pki_creator_args[CA_KEY_FILEPATH]}" "${gateway_pki_creator_args[CA_CERT_FILEPATH]}" || true

  elif [ "${command_tool}" == "${COMMAND_TOOL__CLIENT_PKI_CREATOR}" ]; then
    cmn__create_ca_cert_csr_conf_file "${client_pki_creator_args[CA_CERT_FILEPATH]}" || true
    if cmn__create_private_key_file "${client_pki_creator_args[CLIENT_KEY_FILEPATH]}" "${client_pki_creator_args[KEY_ALGORITHM]}"; then
      rm -f "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}" "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}".csr
    fi
    client__create_cert_openssl_conf "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}" || true
    cmn__create_cert_csr_file "${client_pki_creator_args[CLIENT_KEY_FILEPATH]}" "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}" || true
    cmn__create_non_ca_cert_file "${client_pki_creator_args[CLIENT_CERT_FILEPATH]}" client-cert "${client_pki_creator_args[CERT_EXPIRY_DAYS]}" "${client_pki_creator_args[CA_KEY_FILEPATH]}" "${client_pki_creator_args[CA_CERT_FILEPATH]}" || true
  fi
}

main "$@"
